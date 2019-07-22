using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;

namespace Medidata.MAuth.Core
{
    internal class MAuthAuthenticator
    {
        private readonly MAuthOptionsBase options;
        private readonly MAuthRequestRetrier retrier;
        private readonly IMemoryCache cache = new MemoryCache(new MemoryCacheOptions());
        private readonly MAuthCoreImplementation mAuthCore;

        public Guid ApplicationUuid => options.ApplicationUuid;

        public MAuthAuthenticator(MAuthOptionsBase options)
        {
            if (options.ApplicationUuid == default(Guid))
                throw new ArgumentException(nameof(options.ApplicationUuid));

            if (options.MAuthServiceUrl == null)
                throw new ArgumentNullException(nameof(options.MAuthServiceUrl));

            if (string.IsNullOrWhiteSpace(options.PrivateKey))
                throw new ArgumentNullException(nameof(options.PrivateKey));

            this.options = options;
            mAuthCore = MAuthCoreImplementation.MAuthCore;
            retrier = new MAuthRequestRetrier(options);
        }

        public async Task<bool> AuthenticateRequest(HttpRequestMessage request)
        {
            try
            {
                var authInfo = GetAuthenticationInfo(request);
                var appInfo = await GetApplicationInfo(authInfo.ApplicationUuid);

                return mAuthCore.Verify(authInfo.Payload, await mAuthCore.GetSignature(request, authInfo), appInfo.PublicKey);
            }
            catch (ArgumentException ex)
            {
                throw new AuthenticationException("The request has invalid MAuth authentication headers.", ex);
            }
            catch (RetriedRequestException ex)
            {
                throw new AuthenticationException(
                    "Could not query the application information for the application from the MAuth server.", ex);
            }
            catch (InvalidCipherTextException ex)
            {
                throw new AuthenticationException(
                    "The request verification failed due to an invalid payload information.", ex);
            }
            catch (Exception ex)
            {
                throw new AuthenticationException(
                    "An unexpected error occured during authentication. Please see the inner exception for details.",
                    ex
                );
            }
        }

        private Task<ApplicationInfo> GetApplicationInfo(Guid applicationUuid) =>
            cache.GetOrCreateAsync(applicationUuid, async entry =>
            {
                var response = await retrier.GetSuccessfulResponse(
                    applicationUuid,
                    CreateRequest,
                    requestAttempts: (int)options.MAuthServiceRetryPolicy + 1
                );

                var result = await response.Content.FromResponse();

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
        /// <returns>The authentication information with the payload from the request.</returns>
        public PayloadAuthenticationInfo GetAuthenticationInfo(HttpRequestMessage request)
        {
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);

            if (authHeader == null)
                throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey);

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
