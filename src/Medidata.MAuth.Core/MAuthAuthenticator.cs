using System;
using System.Net.Http;
using System.Threading.Tasks;
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
        private readonly MAuthOptionsBase _options;
        private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
        private readonly ILogger _logger;

        public Guid ApplicationUuid => _options.ApplicationUuid;

        public MAuthAuthenticator(MAuthOptionsBase options, ILogger logger)
        {
            if (options.ApplicationUuid == default(Guid))
                throw new ArgumentException(nameof(options.ApplicationUuid));

            if (options.MAuthServiceUrl == null)
                throw new ArgumentNullException(nameof(options.MAuthServiceUrl));

            if (string.IsNullOrWhiteSpace(options.PrivateKey))
                throw new ArgumentNullException(nameof(options.PrivateKey));

            _options = options;
            _logger = logger;
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
                var parsedHeader = authHeader.ParseAuthenticationHeader();

                if (_options.DisableV1 && version == MAuthVersion.MWS)
                    throw new InvalidVersionException($"Authentication with {version} version is disabled.");

                var authenticated = await Authenticate(request, version, parsedHeader.Uuid).ConfigureAwait(false);
                if (!authenticated && version == MAuthVersion.MWSV2 && !_options.DisableV1)
                {
                    // fall back to V1 authentication
                    authenticated = await Authenticate(request, MAuthVersion.MWS, parsedHeader.Uuid).ConfigureAwait(false);
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
            var appInfo = await GetApplicationInfo(authInfo.ApplicationUuid).ConfigureAwait(false);

            var signature = await mAuthCore.GetSignatureAsync(request, authInfo).ConfigureAwait(false);
            return mAuthCore.Verify(authInfo.Payload, signature, appInfo.PublicKey);
        }

        private Task<ApplicationInfo> GetApplicationInfo(Guid applicationUuid) =>
            _cache.GetOrCreateAsync(applicationUuid, async entry =>
            {
                var retrier = new MAuthRequestRetrier(_options);
                var response = await retrier.GetSuccessfulResponse(
                    applicationUuid,
                    CreateRequest,
                    requestAttempts: (int)_options.MAuthServiceRetryPolicy + 1
                ).ConfigureAwait(false);

                var result = await response.Content.FromResponse().ConfigureAwait(false);

                entry.SetOptions(
                    new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(response.Headers.CacheControl?.MaxAge ?? TimeSpan.FromHours(1))
                );

                return result;
            });

        /// <summary>
        /// Extracts the authentication information from a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request that has the authentication information.</param>
        /// <param name="mAuthCore">Instantiation of mAuthCore class.</param>
        /// <returns>The authentication information with the payload from the request.</returns>
        internal static PayloadAuthenticationInfo GetAuthenticationInfo(HttpRequestMessage request, IMAuthCore mAuthCore)
        {
            var headerKeys = mAuthCore.GetHeaderKeys();
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(headerKeys.mAuthHeaderKey);

            if (authHeader == null)
            {
                throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");
            }

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(headerKeys.mAuthTimeHeaderKey);

            if (signedTime == default(long))
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
    }
}
