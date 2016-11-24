using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Newtonsoft.Json;

namespace Medidata.MAuth.Tests
{
    [ExcludeFromCodeCoverage]
    internal class MAuthServerHandler : HttpMessageHandler
    {
        private static readonly Guid clientUuid = new Guid("192cce84-8466-490e-b03e-074f82da3ee2");

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authInfo = request.GetAuthenticationInfo();

            if (!await authInfo.Payload.Verify(
                await request.GetSignature(authInfo),
                TestExtensions.ServerPublicKey
            ))
                return new HttpResponseMessage(HttpStatusCode.Forbidden);

            if (!request.RequestUri.AbsolutePath.Equals(
                $"{Constants.MAuthTokenRequestPath}{clientUuid.ToHyphenString()}.json",
                StringComparison.OrdinalIgnoreCase))
                return new HttpResponseMessage(HttpStatusCode.NotFound);


            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(
                    JsonConvert.SerializeObject(new
                    {
                        security_token = new ApplicationInfo()
                        {
                            Uuid = clientUuid,
                            Name = "Medidata.MAuth.Tests",
                            CreationDate = new DateTimeOffset(2016, 8, 1, 0, 0, 0, TimeSpan.Zero),
                            PublicKey = TestExtensions.ClientPublicKey
                        }
                    })
                )
            };
        }
    }
}
