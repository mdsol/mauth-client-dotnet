using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    internal class MAuthRequestRetrier
    {
        private readonly HttpClient client;

        public MAuthRequestRetrier(MAuthOptionsBase options, MAuthVersion version)
        {
            var signingHandler = new MAuthSigningHandler(options: new MAuthSigningOptions()
            {
                ApplicationUuid = options.ApplicationUuid,
                PrivateKey = options.PrivateKey,
            },
            innerHandler: options.MAuthServerHandler ?? new HttpClientHandler()
            );

            client = new HttpClient(signingHandler)
            {
                Timeout = TimeSpan.FromSeconds(options.AuthenticateRequestTimeoutSeconds)
            };
        }

        public async Task<HttpResponseMessage> GetSuccessfulResponse(Guid applicationUuid,
            Func<Guid, HttpRequestMessage> requestFactory, int requestAttempts)
        {
            if (requestFactory == null)
                throw new ArgumentNullException(nameof(requestFactory));

            if (requestAttempts <= 0)
                throw new ArgumentOutOfRangeException(
                    nameof(requestAttempts),
                    requestAttempts,
                    "Request attempts was out of range. Must be greater than zero."
                );

            RetriedRequestException exception = null;
            
            int remainingAttempts = requestAttempts;
            while (remainingAttempts > 0)
            {
                var request = requestFactory?.Invoke(applicationUuid);

                if (request == null)
                    throw new ArgumentException(
                        "The provided request factory function resulted null request.",
                        nameof(requestFactory)
                    );

                var result = await client.SendAsync(request).ConfigureAwait(continueOnCapturedContext: false);

                if (result.IsSuccessStatusCode)
                    return result;

                if (exception == null)
                {
                    exception = new RetriedRequestException(
                        $"Could not get a successful response from the MAuth Service after {requestAttempts} attempts. " +
                        "Please see the responses for each attempt in the exception's Responses field.")
                    {
                        Request = request
                    };
                }

                exception.Responses.Add(result);
                remainingAttempts--;
            }

            throw exception;
        }
    }
}