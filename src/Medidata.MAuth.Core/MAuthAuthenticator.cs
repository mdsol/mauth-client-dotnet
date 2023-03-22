using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Caching;
using Medidata.MAuth.Core.Exceptions;
using Microsoft.Extensions.Caching.Memory;
using Org.BouncyCastle.Crypto;
using Medidata.MAuth.Core.Models;
using Microsoft.Extensions.Logging;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Medidata.MAuth.Core
{
    internal class MAuthAuthenticator
    {
        private const int AllowedDriftSeconds = 300;
        private static readonly TimeSpan AllowedDriftTimeSpan = TimeSpan.FromSeconds(AllowedDriftSeconds);

        private readonly ICacheService _cache;
        private readonly MAuthOptionsBase _options;
        private readonly ILogger _logger;
        private readonly IDateTimeOffsetWrapper _dateTimeOffsetWrapper;
        private readonly Lazy<HttpClient> _lazyHttpClient;

        public Guid ApplicationUuid => _options.ApplicationUuid;

        public MAuthAuthenticator(MAuthOptionsBase options, ILogger logger, ICacheService cacheService = null)
        {
            if (options.ApplicationUuid == default)
                throw new ArgumentException(nameof(options.ApplicationUuid));

            if (options.MAuthServiceUrl == null)
                throw new ArgumentNullException(nameof(options.MAuthServiceUrl));

            if (string.IsNullOrWhiteSpace(options.PrivateKey))
                throw new ArgumentNullException(nameof(options.PrivateKey));

            _cache = cacheService ?? new MemoryCacheService(new MemoryCache(new MemoryCacheOptions()));
            _options = options;
            _logger = logger;
            _lazyHttpClient = new Lazy<HttpClient>(() => CreateHttpClient(options));
            _dateTimeOffsetWrapper = options.DateTimeOffsetWrapper;
        }

        /// <summary>
        /// Verifies if the <see cref="HttpRequestMessage"/> request is authenticated or not.
        /// </summary>
        /// <param name="request">The <see cref="HttpRequestMessage"/> request.</param>
        /// <returns>A task object of the boolean value that verifies if the request is authenticated or not.</returns>
        public async Task<bool> AuthenticateRequest(HttpRequestMessage request)
        {
            try
            {
                _logger.LogInformation("Initiating Authentication of the request.");

                var authHeader = request.GetAuthHeaderValue();
                var version = authHeader.GetVersionFromAuthenticationHeader();
                var (Uuid, Base64Payload) = authHeader.ParseAuthenticationHeader();

                if (_options.DisableV1 && version == MAuthVersion.MWS)
                    throw new InvalidVersionException($"Authentication with {version} version is disabled.");

                var authenticated = await Authenticate(request, version, Uuid).ConfigureAwait(false);
                if (!authenticated && version == MAuthVersion.MWSV2 && !_options.DisableV1)
                {
                    // fall back to V1 authentication
                    authenticated = await Authenticate(request, MAuthVersion.MWS, Uuid).ConfigureAwait(false);
                    _logger.LogWarning("Completed successful authentication attempt after fallback to V1");
                }
                return authenticated;
            }
            catch (ArgumentException ex)
            {
                _logger.LogError(ex, "Unable to authenticate due to invalid MAuth authentication headers.");
                throw new AuthenticationException("The request has invalid MAuth authentication headers.", ex);
            }
            catch (RetriedRequestException ex)
            {
                _logger.LogError(ex, "Unable to query the application information from MAuth server.");
                throw new AuthenticationException(
                    "Could not query the application information for the application from the MAuth server.", ex);
            }
            catch (InvalidCipherTextException ex)
            {
                _logger.LogWarning(ex, "Unable to authenticate due to invalid payload information.");
                throw new AuthenticationException(
                    "The request verification failed due to an invalid payload information.", ex);
            }
            catch (InvalidVersionException ex)
            {
                _logger.LogError(ex, "Unable to authenticate due to invalid version.");
                throw new InvalidVersionException(ex.Message, ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unable to authenticate due to unexpected error.");
                throw new AuthenticationException(
                    "An unexpected error occured during authentication. Please see the inner exception for details.",
                    ex
                );
            }
        }

        private async Task<bool> Authenticate(HttpRequestMessage request, MAuthVersion version, Guid signedAppUuid)
        {
            var logMessage = "Mauth-client attempting to authenticate request from app with mauth app uuid " +
                $"{signedAppUuid} to app with mauth app uuid {_options.ApplicationUuid} using version {version}";
            _logger.LogInformation(logMessage);

            var mAuthCore = MAuthCoreFactory.Instantiate(version);
            var authInfo = GetAuthenticationInfo(request, mAuthCore);

            if (!IsSignatureTimeValid(authInfo.SignedTime))
            {
                return false;
            }

            var appInfo = await _cache.GetOrCreateWithLock(
                    authInfo.ApplicationUuid.ToString(),
                    () => SendApplicationInfoRequest(authInfo.ApplicationUuid)).ConfigureAwait(false);

            var signature = await mAuthCore.GetSignature(request, authInfo).ConfigureAwait(false);
            return mAuthCore.Verify(authInfo.Payload, signature, appInfo.PublicKey);
        }

        private bool IsSignatureTimeValid(DateTimeOffset signedTime)
        {
            var now = _dateTimeOffsetWrapper.GetUtcNow();
            var lowerBound = now - AllowedDriftTimeSpan;
            var upperBound = now + AllowedDriftTimeSpan;
            var isValid = signedTime >= lowerBound && signedTime <= upperBound;

            if (!isValid)
            {
                _logger.LogInformation(
                    "Time verification failed. {signedTime} is not within {AllowedDriftSeconds} seconds of #{now}",
                    signedTime,
                    AllowedDriftSeconds,
                    now);
            }

            return isValid;
        }
        
        private async Task<CacheResult<ApplicationInfo>> SendApplicationInfoRequest(Guid applicationUuid)
        {
            var logMessage = "Mauth-client requesting from mAuth service application info not available " +
                             $"in the local cache for app uuid {applicationUuid}.";
            _logger.LogInformation(logMessage);

            var retrier = new MAuthRequestRetrier(_lazyHttpClient.Value);
            var response = await retrier.GetSuccessfulResponse(
                applicationUuid,
                CreateRequest,
                requestAttempts: (int)_options.MAuthServiceRetryPolicy + 1
            ).ConfigureAwait(false);

            var result = await response.Content.FromResponse().ConfigureAwait(false);
            
            logMessage = $"Mauth-client application info for app uuid {applicationUuid} cached in memory.";
            _logger.LogInformation(logMessage);

            var cacheResult = new CacheResult<ApplicationInfo>
            {
                ShouldCache = true,
                Result = result,
                AbsoluteCacheDuration = response.Headers.CacheControl?.MaxAge ?? TimeSpan.FromMinutes(5),
            };
            
            return cacheResult;
                
        }

        /// <summary>
        /// Extracts the authentication information from a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request that has the authentication information.</param>
        /// <param name="mAuthCore">Instantiation of mAuthCore class.</param>
        /// <returns>The authentication information with the payload from the request.</returns>
        internal static PayloadAuthenticationInfo GetAuthenticationInfo(HttpRequestMessage request, IMAuthCore mAuthCore)
        {
            var (mAuthHeaderKey, mAuthTimeHeaderKey) = mAuthCore.GetHeaderKeys();
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(mAuthHeaderKey);

            if (authHeader == null)
            {
                throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");
            }

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(mAuthTimeHeaderKey);

            if (signedTime == default)
            {
                throw new ArgumentException("Invalid MAuth signed time header value.", nameof(signedTime));
            }

            var (uuid, payload) = authHeader.ParseAuthenticationHeader();

            return new PayloadAuthenticationInfo
            {
                ApplicationUuid = uuid,
                Payload = Convert.FromBase64String(payload),
                SignedTime = signedTime.FromUnixTimeSeconds()
            };
        }

        private HttpRequestMessage CreateRequest(Guid applicationUuid) =>
            new HttpRequestMessage(HttpMethod.Get, new Uri(_options.MAuthServiceUrl,
                $"{Constants.MAuthTokenRequestPath}{applicationUuid.ToHyphenString()}.json"));

        private HttpClient CreateHttpClient(MAuthOptionsBase options)
        {
            var signingHandler = new MAuthSigningHandler(options: new MAuthSigningOptions()
                {
                    ApplicationUuid = options.ApplicationUuid,
                    PrivateKey = options.PrivateKey,
                },
                innerHandler: options.MAuthServerHandler ?? new HttpClientHandler()
            );

            return new HttpClient(signingHandler)
            {
                Timeout = TimeSpan.FromSeconds(options.AuthenticateRequestTimeoutSeconds)
            };
        }
    }
}
