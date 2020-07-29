using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.ProtocolTestSuite;
using Newtonsoft.Json;

namespace Medidata.MAuth.Tests.Infrastructure
{
    internal class MAuthServerHandler : HttpMessageHandler
    {
        private static readonly Guid clientUuid = new Guid("192cce84-8466-490e-b03e-074f82da3ee2");
        private int currentNumberOfAttempts = 0;

        public int SucceedAfterThisManyAttempts { get; set; } = 1;

        private static ProtocolTestSuiteHelper _protocolSuiteHelper = new ProtocolTestSuiteHelper();

        public static readonly string SigningPublicKey = _protocolSuiteHelper.GetPublicKey().Result;
        public static readonly Guid SigningAppUuid = _protocolSuiteHelper.ReadSignInAppUuid().Result;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            currentNumberOfAttempts += 1;
            var version = request.GetAuthHeaderValue().GetVersionFromAuthenticationHeader();
            var mAuthCore = MAuthCoreFactory.Instantiate(version);

            if (currentNumberOfAttempts < SucceedAfterThisManyAttempts)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            var authInfo = MAuthAuthenticator.GetAuthenticationInfo(request, mAuthCore);

            if (!mAuthCore.Verify(authInfo.Payload, 
                await mAuthCore.GetSignature(request, authInfo),
                TestExtensions.ServerPublicKey
            ))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized) { RequestMessage = request };

            if (!request.RequestUri.AbsolutePath.Equals(
                $"{Constants.MAuthTokenRequestPath}{clientUuid.ToHyphenString()}.json",
                StringComparison.OrdinalIgnoreCase) &&
                !request.RequestUri.AbsolutePath.Equals(
                $"{Constants.MAuthTokenRequestPath}{SigningAppUuid.ToHyphenString()}.json",
                StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request };
            }

            bool isProtocolSuiteTest = request.RequestUri.AbsolutePath.Contains(
                SigningAppUuid.ToHyphenString());

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(
                    JsonConvert.SerializeObject(new
                    {
                        security_token = new ApplicationInfo()
                        {
                            Uuid = isProtocolSuiteTest ? SigningAppUuid : clientUuid,
                            Name = "Medidata.MAuth.Tests",
                            CreationDate = new DateTimeOffset(2016, 8, 1, 0, 0, 0, TimeSpan.Zero),
                            PublicKey = isProtocolSuiteTest ? SigningPublicKey : TestExtensions.ClientPublicKey
                        }
                    })
                )
            };
        }
    }
}
