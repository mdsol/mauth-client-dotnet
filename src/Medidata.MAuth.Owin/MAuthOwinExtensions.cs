using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Microsoft.Owin;
using Version = Medidata.MAuth.Core.Models.Version;

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
            var result = new HttpRequestMessage(new HttpMethod(request.Method), request.Uri)
            {
                Content = new StreamContent(request.Body)
            };

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
        /// <param name="mAuthVersion">Determines if the authentication uses V2 or V1 method</param>
        /// <returns>
        /// This method returns <see langword="true"/> if it successfully authenticated the request;
        /// otherwise it will return either <see langword="false"/> if the method should ignore exceptions or
        /// will throw an exception if any errors occurred during the authentication.</returns>
        public static async Task<bool> TryAuthenticate(
            this IOwinContext context, MAuthAuthenticator authenticator, bool shouldIgnoreExceptions, Enum mAuthVersion)
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

        /// <summary>
        /// Tests whether the provided <see cref="IOwinContext"/> request's body is a seekable stream and if it is not,
        /// it will replace the body stream with a seekable memory stream.
        /// </summary>
        /// <param name="context">The http context that contains the <see cref="IOwinRequest"/> with a body.</param>
        /// <returns>A task that represents the asynchronous copy operation.</returns>
        public static async Task EnsureRequestBodyStreamSeekable(this IOwinContext context)
        {
            if (context.Request.Body == null || context.Request.Body == Stream.Null || context.Request.Body.CanSeek)
                return;

            var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body);

            body.Rewind();

            context.Request.Body = body;
        }
    }
}
