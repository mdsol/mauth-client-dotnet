using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.Tests
{
    [ExcludeFromCodeCoverage]
    internal class TestData
    {
        public HttpMethod Method { get; private set; }

        public string Payload { get; private set; }

        public DateTimeOffset SignedTime { get; private set; }

        public string Content { get; private set; }

        public long SignedTimeUnixSeconds => SignedTime.ToUnixTimeSeconds();

        public HttpRequestMessage Request => new HttpRequestMessage(Method, "http://localhost:29999")
        {
            Content = Content != null ? new StringContent(Content) : null
        };

        public string MAuthHeader => $"MWS {TestExtensions.ClientUuid}:{Payload}";

        public static async Task<TestData> For(string method)
        {
            var lines =
                (await TestExtensions.GetStringFromResource($"Medidata.MAuth.Tests.Mocks.Requests.{method}.txt"))
                .Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            return new TestData()
            {
                Method = new HttpMethod(method),
                Payload = lines[0],
                SignedTime = DateTimeOffset.Parse(lines[1]),
                Content = lines.Length >= 3 ? lines[2] : null
            };
        }
    }
}
