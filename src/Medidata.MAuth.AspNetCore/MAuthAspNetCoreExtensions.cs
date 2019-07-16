using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Version = Medidata.MAuth.Core.Models.Version;

namespace Medidata.MAuth.AspNetCore
{
    internal static class MAuthAspNetCoreExtensions
    {
        /// <summary>
        /// Converts an <see cref="HttpRequest"/> object to an equivalent <see cref="HttpRequestMessage"/> object. 
        /// </summary>
        /// <param name="request">The request to convert.</param>
        /// <returns>The request message.</returns>
        public static HttpRequestMessage ToHttpRequestMessage(this HttpRequest request)
        {
            var result = new HttpRequestMessage(new HttpMethod(request.Method), request.GetEncodedUrl())
            {
                Content = new StreamContent(request.Body)
            };

            foreach (var header in request.Headers)
            {
                if (!result.Headers.TryAddWithoutValidation(header.Key, (IEnumerable<string>)header.Value))
                    result.Content.Headers.TryAddWithoutValidation(header.Key, (IEnumerable<string>)header.Value);
            }

            return result;
        }

        /// <summary>
        /// Attempts to authenticate the provided request in the <see cref="HttpContext"/> with the provided
        /// authenticator.
        /// </summary>
        /// <param name="context">The context of the request.</param>
        /// <param name="authenticator">The authenticator which will attempt the request authentication.</param>
        /// <param name="shouldIgnoreExceptions">Determines if any exceptions during the authentication
        /// should be thrown.</param>
        /// <param name="mAuthVersion">Determines if the authentication uses V2 or V1 method</param>
        /// <returns>
        /// This method returns <see langword="true"/> if it successfully authenticated the request;
        /// otherwise it will return either <see langword="false"/> if the method should ignore exceptions or
        /// will throw an exception if any errors occurred during the authentication.
        /// </returns>
        public static async Task<bool> TryAuthenticate(
            this HttpContext context, MAuthAuthenticator authenticator, bool shouldIgnoreExceptions, Enum mAuthVersion)
        {
            try
            {
                if (mAuthVersion.Equals(Version.V2))
                    return await authenticator.AuthenticateRequestV2(context.Request.ToHttpRequestMessage());

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
