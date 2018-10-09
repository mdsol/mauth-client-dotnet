using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;

namespace Medidata.MAuth.HttpModule
{
    public static class HttpExtensions
    {
        public static HttpRequestMessage GetRequestForContext(this HttpContext context)
        {
            var request = context.Request;
            var requestMessage = new HttpRequestMessage(new HttpMethod(request.HttpMethod), request.Url);

            foreach (string key in request.Headers)
                requestMessage.Headers.TryAddWithoutValidation(key, request.Headers[key]);

            var memoryStream = new MemoryStream();
            if (request.ContentLength > 0)
            {
                request.InputStream.CopyTo(memoryStream);
                memoryStream.Position = 0;
                requestMessage.Content = new StreamContent(memoryStream);
            }

            return requestMessage;
        }
        public static HttpResponseBase GetResponseForContext(this HttpContext context)
        {
            return new HttpResponseWrapper(context.Response);
        }

        public static bool PathIsIn(this HttpRequestMessage request, IEnumerable<string> paths)
        {
            return
                request.RequestUri?.AbsolutePath != null &&
                paths
                    .Any(path => request.RequestUri.AbsolutePath.ToLower().StartsWith(path.ToLower()));
        }
    }
}
