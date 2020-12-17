using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core
{
    internal static class HttpRequestMessageExtensions
    {
        public async static Task<byte[]> GetRequestContentAsBytesAsync(this HttpRequestMessage request)
        {
            return request.Content is null
                    ? Array.Empty<byte>()
                    : await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

#if NET5_0
        public static byte[] GetRequestContentAsBytes(this HttpRequestMessage request)
        {
            using (var memoryStream = new MemoryStream())
            {
                if (request.Content != null)
                {
                    request.Content.ReadAsStream().CopyTo(memoryStream);
                }
                return memoryStream.ToArray();
            }
        }
#endif
    }
}
