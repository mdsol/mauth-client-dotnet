using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Exceptions;
using Microsoft.Extensions.Caching.Memory;
using Org.BouncyCastle.Crypto;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    internal class MAuthAuthenticator
    {
        private readonly MAuthOptionsBase options;
        private readonly IMemoryCache cache = new MemoryCache(new MemoryCacheOptions());

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
        }

        public async Task<bool> AuthenticateRequest(HttpRequestMessage request)
        {
            try
            {
                var version = request.GetAuthHeaderValue().GetVersionFromAuthenticationHeader();

                if (options.DisableV1 && version == MAuthVersion.MWS)
                    throw new InvalidVersionException($"Authentication with {version} version is disabled.");

                var mAuthCore = MAuthCoreFactory.Instantiate(version);
                var authInfo = mAuthCore.GetAuthenticationInfo(request);
                var appInfo = await GetApplicationInfo(authInfo.ApplicationUuid, version);

                return mAuthCore.Verify(authInfo.Payload, await mAuthCore.GetSignature(request, authInfo),
                    appInfo.PublicKey);
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
            catch (InvalidVersionException ex)
            {
                throw new InvalidVersionException(ex.Message, ex);
            }
            catch (Exception ex)
            {
                throw new AuthenticationException(
                    "An unexpected error occured during authentication. Please see the inner exception for details.",
                    ex
                );
            }
        }

        private Task<ApplicationInfo> GetApplicationInfo(Guid applicationUuid, MAuthVersion version) =>
            cache.GetOrCreateAsync(applicationUuid, async entry =>
            {
                var mAuthCore = MAuthCoreFactory.Instantiate(version);
                var tokenRequestPath = mAuthCore.GetMAuthTokenRequestPath();
                var retrier = new MAuthRequestRetrier(options, version);
                var response = await retrier.GetSuccessfulResponse(
                    applicationUuid,
                    CreateRequest, tokenRequestPath,
                    requestAttempts: (int)options.MAuthServiceRetryPolicy + 1
                );

                var result = await response.Content.FromResponse();

                entry.SetOptions(
                    new MemoryCacheEntryOptions()
                        .SetAbsoluteExpiration(response.Headers.CacheControl?.MaxAge ?? TimeSpan.FromHours(1))
                );

                return result;
            });

        private HttpRequestMessage CreateRequest(Guid applicationUuid, string tokenRequestPath) =>
            new HttpRequestMessage(HttpMethod.Get, new Uri(options.MAuthServiceUrl,
                $"{tokenRequestPath}{applicationUuid.ToHyphenString()}.json"));
    }
}
