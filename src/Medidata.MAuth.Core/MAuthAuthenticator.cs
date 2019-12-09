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
        private readonly MAuthOptionsBase options;
        private readonly IMemoryCache cache = new MemoryCache(new MemoryCacheOptions());
        private readonly ILogger logger;

        public Guid ApplicationUuid => options.ApplicationUuid;

        public MAuthAuthenticator(MAuthOptionsBase options, ILogger logger)
        {
            if (options.ApplicationUuid == default(Guid))
                throw new ArgumentException(nameof(options.ApplicationUuid));

            if (options.MAuthServiceUrl == null)
                throw new ArgumentNullException(nameof(options.MAuthServiceUrl));

            if (string.IsNullOrWhiteSpace(options.PrivateKey))
                throw new ArgumentNullException(nameof(options.PrivateKey));

            this.options = options;
            this.logger = logger;
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
                logger.LogInformation("Initiating Authentication of the request.");
                var version = request.GetAuthHeaderValue().GetVersionFromAuthenticationHeader();

                if (options.DisableV1 && version == MAuthVersion.MWS)
                    throw new InvalidVersionException($"Authentication with {version} version is disabled.");

                var mAuthCore = MAuthCoreFactory.Instantiate(version);
                var authInfo = GetAuthenticationInfo(request, version);
                var logMessage = "Mauth-client attempting to authenticate request from app with mauth app uuid" +
                        $" {authInfo.ApplicationUuid} using version {version}";
                logger.LogInformation(logMessage);

                var appInfo = await GetApplicationInfo(authInfo.ApplicationUuid, version).ConfigureAwait(false);
                var signature = await mAuthCore.GetSignature(request, authInfo).ConfigureAwait(false);

                return mAuthCore.Verify(authInfo.Payload, signature, appInfo.PublicKey);
            }
            catch (ArgumentException ex)
            {
                logger.LogError(ex, "Unable to authenticate due to invalid MAuth authentication headers.");
                throw new AuthenticationException("The request has invalid MAuth authentication headers.", ex);
            }
            catch (RetriedRequestException ex)
            {
                logger.LogError(ex, "Unable to query the application information from MAuth server.");
                throw new AuthenticationException(
                    "Could not query the application information for the application from the MAuth server.", ex);
            }
            catch (InvalidCipherTextException ex)
            {
                logger.LogWarning(ex, "Unable to authenticate due to invalid payload information.");
                throw new AuthenticationException(
                    "The request verification failed due to an invalid payload information.", ex);
            }
            catch (InvalidVersionException ex)
            {
                logger.LogError(ex, "Unable to authenticate due to invalid version.");
                throw new InvalidVersionException(ex.Message, ex);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unable to authenticate due to unexpected error.");
                throw new AuthenticationException(
                    "An unexpected error occured during authentication. Please see the inner exception for details.",
                    ex
                );
            }
        }

        private Task<ApplicationInfo> GetApplicationInfo(Guid applicationUuid, MAuthVersion version) =>
            cache.GetOrCreateAsync(applicationUuid, async entry =>
            {
                var retrier = new MAuthRequestRetrier(options, version);
                var response = await retrier.GetSuccessfulResponse(
                    applicationUuid,
                    CreateRequest,
                    requestAttempts: (int)options.MAuthServiceRetryPolicy + 1
                ).ConfigureAwait(false);

                var result = await response.Content.FromResponse().ConfigureAwait(false);

                entry.SetOptions(
                    new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(response.Headers.CacheControl?.MaxAge ?? TimeSpan.FromHours(1))
                );

                return result;
            });

        private HttpRequestMessage CreateRequest(Guid applicationUuid) =>
            new HttpRequestMessage(HttpMethod.Get, new Uri(options.MAuthServiceUrl,
                $"{Constants.MAuthTokenRequestPath}{applicationUuid.ToHyphenString()}.json"));

        /// <summary>
        /// Extracts the authentication information from a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request that has the authentication information.</param>
        /// <param name="version">Enum value of the MAuthVersion.</param>
        /// <returns>The authentication information with the payload from the request.</returns>
        internal PayloadAuthenticationInfo GetAuthenticationInfo(HttpRequestMessage request, MAuthVersion version)
        {
            var mAuthCore = MAuthCoreFactory.Instantiate(version);
            var headerKeys = mAuthCore.GetHeaderKeys();
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(headerKeys.mAuthHeaderKey);

            if (authHeader == null)
                throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(headerKeys.mAuthTimeHeaderKey);

            if (signedTime == default(long))
                throw new ArgumentException("Invalid MAuth signed time header value.", nameof(signedTime));

            var (uuid, payload) = authHeader.ParseAuthenticationHeader();

            return new PayloadAuthenticationInfo()
            {
                ApplicationUuid = uuid,
                Payload = Convert.FromBase64String(payload),
                SignedTime = signedTime.FromUnixTimeSeconds()
            };
        }
    }
}
