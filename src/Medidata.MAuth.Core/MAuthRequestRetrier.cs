using System;
using System.Collections.Generic;
using System.Linq;
#if !NETSTANDARD1_4
using System.Net.Cache;
#endif
using System.Net.Http;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core
{
    internal class MAuthRequestRetrier
    {
        private readonly HttpClient client;
        private RetriedRequestException exception;

        public MAuthRequestRetrier(MAuthOptionsBase options)
        {
            var signingHandler = new MAuthSigningHandler(options: new MAuthSigningOptions()
            {
                ApplicationUuid = options.ApplicationUuid,
                PrivateKey = options.PrivateKey
            },
            innerHandler: options.MAuthServerHandler ??
#if NETSTANDARD1_4
                new HttpClientHandler()
#else
                new WebRequestHandler()
                {
                    CachePolicy = new RequestCachePolicy(RequestCacheLevel.Default)
                }
#endif
            );

            client = new HttpClient(signingHandler);
            client.Timeout = TimeSpan.FromSeconds(options.AuthenticateRequestTimeoutSeconds);
        }

        public async Task<HttpResponseMessage> GetSuccessfulResponse(Guid applicationUuid,
            Func<Guid, HttpRequestMessage> requestFactory, int remainingAttempts)
        {
            var request = requestFactory?.Invoke(applicationUuid);

            if (request == null)
                throw new ArgumentNullException(
                    "No request function provided or the provided request function resulted null request.",
                    nameof(requestFactory)
                );

            exception = exception ?? new RetriedRequestException(
                $"Could not get a successful response from the MAuth Service after {remainingAttempts} attempts. " +
                "Please see the responses for each attempt in the exception's Responses field.");

            if (remainingAttempts == 0)
                throw exception;

            var result = await client.SendAsync(request).ConfigureAwait(continueOnCapturedContext: false);

            exception.Responses.Add(result);

            return result.IsSuccessStatusCode ?
                result : await GetSuccessfulResponse(applicationUuid, requestFactory, remainingAttempts - 1);
        }
    }
}
