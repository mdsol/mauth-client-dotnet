using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Text;
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

            if (request.Body.CanSeek)
                request.Body.Seek(0, SeekOrigin.Begin);

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

        public static async Task EnsureRequestBodyStreamSeekable(this IOwinContext context)
        {
            if (context.Request.Body == null || context.Request.Body == Stream.Null || context.Request.Body.CanSeek)
                return;

            var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
            var charset = context.Request.GetContentTypeOrDefault()?.CharSet;
            var encoding = Encoding.GetEncodings().SingleOrDefault(e => e.Name == charset)?.GetEncoding() ??
                Encoding.UTF8;

            context.Request.Body = new MemoryStream(encoding.GetBytes(body));
        }

        public static ContentType GetContentTypeOrDefault(this IOwinRequest request)
        {
            try
            {
                return new ContentType(request.ContentType);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
