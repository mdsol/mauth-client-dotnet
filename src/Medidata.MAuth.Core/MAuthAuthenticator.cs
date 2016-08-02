using System;
using System.Net.Cache;
using System.Net.Http;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Medidata.MAuth.Core
{
    internal class MAuthAuthenticator
    {
        private readonly MAuthOptions options;

        public Guid ApplicationUuid => options.ApplicationUuid;

        public MAuthAuthenticator(MAuthOptions options)
        {
            if (options.ApplicationUuid == default(Guid))
                throw new ArgumentException(nameof(options.ApplicationUuid));

            if (options.MAuthServiceUrl == null)
                throw new ArgumentNullException(nameof(options.MAuthServiceUrl));

            if (string.IsNullOrWhiteSpace(options.PrivateKey))
                throw new ArgumentNullException(nameof(options.PrivateKey));

            this.options = options;
        }

        public async Task<bool> AuthenticateRequest(HttpRequestMessage request)
        {
            try
            {
                var authInfo = request.GetAuthenticationInfo();
                var appInfo = await GetApplicationInfo(authInfo.ApplicationUuid);

                return await authInfo.Payload.Verify(await request.GetSignature(authInfo), appInfo.PublicKey);
            }
            catch (ArgumentException ex)
            {
                throw new AuthenticationException("The request has invalid MAuth authentication headers.", ex);
            }
            catch (HttpRequestException ex)
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
                    "An unexpected error occured during authentication. Please see the inner exception for details",
                    ex
                );
            }
        }

        public Task<HttpRequestMessage> SignRequest(HttpRequestMessage request)
        {
            return request.AddAuthenticationInfo(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey
            });
        }

        private async Task<ApplicationInfo> GetApplicationInfo(Guid applicationUuid)
        {
            var innerHandler = options.MAuthServerHandler ?? new WebRequestHandler()
            {
                CachePolicy = new RequestCachePolicy(RequestCacheLevel.Default)
            };

            using (var client = new HttpClient(new MAuthSigningHandler(options, innerHandler)))
            {
                client.Timeout = TimeSpan.FromSeconds(options.AuthenticateRequestTimeoutSeconds);

                var response = await client.SendAsync(new HttpRequestMessage(
                    HttpMethod.Get,
                    new Uri(
                        options.MAuthServiceUrl,
                        $"{Constants.MAuthTokenRequestPath}{applicationUuid.ToHyphenString()}.json")
                ));

                response.EnsureSuccessStatusCode();

                return await response.Content.FromResponse();
            }
        }
    }
}
