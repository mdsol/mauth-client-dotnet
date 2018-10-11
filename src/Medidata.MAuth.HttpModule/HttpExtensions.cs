using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;

namespace Medidata.MAuth.HttpModule
{
    /// <summary>
    /// TODO..
    /// </summary>
    public static class HttpExtensions
    {
        /// <summary>
        /// TODO..
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public static HttpRequestMessage GetRequestForContext(this HttpRequest request)
        {
            var requestMessage = new HttpRequestMessage(new HttpMethod(request.HttpMethod), request.Url);

            if (request.InputStream == null || request.InputStream == Stream.Null || request.InputStream.CanSeek)
                requestMessage.Content = new StreamContent(request.InputStream);

            foreach (string key in request.Headers)
            {
                if (!requestMessage.Headers.TryAddWithoutValidation(key, request.Headers[key]))
                    requestMessage.Content.Headers.TryAddWithoutValidation(key, request.Headers[key]);
            }

            return requestMessage;
        }

        /// <summary>
        /// TODO..
        /// </summary>
        /// <param name="request"></param>
        /// <param name="paths"></param>
        /// <returns></returns>
        public static bool PathIsIn(this HttpRequestMessage request, IEnumerable<string> paths)
        {
            return
                request.RequestUri?.AbsolutePath != null &&
                paths
                    .Any(path => request.RequestUri.AbsolutePath.ToLower().StartsWith(path.ToLower()));
        }
    }
}
