using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Owin;

namespace Medidata.MAuth.Owin
{
    internal static class MAuthOwinExtensions
    {
        /// <summary>
        /// Converts an <see cref="IOwinRequest"/> object to an equivalent <see cref="HttpRequestMessage"/> object. 
        /// </summary>
        /// <param name="request">The request to convert.</param>
        /// <returns>The request message.</returns>
        public static HttpRequestMessage ToHttpRequestMessage(this IOwinRequest request)
        {
            var result = new HttpRequestMessage(new HttpMethod(request.Method), request.Uri);
            result.Content = new StreamContent(request.Body);
            
            foreach (var header in request.Headers)
            {
                if (!result.Headers.TryAddWithoutValidation(header.Key, header.Value))
                    result.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return result;
        }

        /// <summary>
        /// Attempts to authenticate the provided request in the <see cref="IOwinContext"/> with the provided
        /// authenticator.
        /// </summary>
        /// <param name="context">The context of the request.</param>
        /// <param name="authenticator">The authenticator which will attempt the request authentication.</param>
        /// <param name="shouldIgnoreExceptions">Determines if any exceptions during the authentication
        /// should be thrown.</param>
        /// <returns>
        /// This method returns <see langword="true"/> if it successfully authenticated the request;
        /// otherwise it will return either <see langword="false"/> if the method should ignore exceptions or
        /// will throw an exception if any errors occurred during the authentication.</returns>
        public static async Task<bool> TryAuthenticate(
            this IOwinContext context, MAuthAuthenticator authenticator, bool shouldIgnoreExceptions)
        {
            try
            {
                return await authenticator.AuthenticateRequest(context.Request.ToHttpRequestMessage());
            }
            catch (Exception)
            {
                if (shouldIgnoreExceptions)
                    return false;

                throw;
            }
        }
    }
}
