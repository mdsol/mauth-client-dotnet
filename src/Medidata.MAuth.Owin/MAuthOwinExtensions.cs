using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Owin;

namespace Medidata.MAuth.Owin
{
    internal static class MAuthOwinExtensions
    {
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
