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
        private MAuthServerHandler() { }

        private static readonly Guid _clientUuid = new Guid("192cce84-8466-490e-b03e-074f82da3ee2");
        private int _currentNumberOfAttempts = 0;

        public int SucceedAfterThisManyAttempts { get; set; } = 1;

        private static string _signingPublicKey;
        private static Guid _signingAppUuid;

        private async Task<MAuthServerHandler> InitializeAsync()
        {
            var protocolSuite = new ProtocolTestSuiteHelper();
            _signingPublicKey = await protocolSuite.GetPublicKey();
            _signingAppUuid = await protocolSuite.ReadSignInAppUuid();
            return this;
        }

        public static Task<MAuthServerHandler> CreateAsync()
        {
            var ret = new MAuthServerHandler();
            return ret.InitializeAsync();
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _currentNumberOfAttempts += 1;
            var version = request.GetAuthHeaderValue().GetVersionFromAuthenticationHeader();
            var mAuthCore = MAuthCoreFactory.Instantiate(version);

            if (_currentNumberOfAttempts < SucceedAfterThisManyAttempts)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            var authInfo = MAuthAuthenticator.GetAuthenticationInfo(request, mAuthCore);

            if (!mAuthCore.Verify(authInfo.Payload, 
                await mAuthCore.GetSignatureAsync(request, authInfo),
                TestExtensions.ServerPublicKey
            ))
                return new HttpResponseMessage(HttpStatusCode.Unauthorized) { RequestMessage = request };

            if (!request.RequestUri.AbsolutePath.Equals(
                $"{Constants.MAuthTokenRequestPath}{_clientUuid.ToHyphenString()}.json",
                StringComparison.OrdinalIgnoreCase) &&
                !request.RequestUri.AbsolutePath.Equals(
                $"{Constants.MAuthTokenRequestPath}{_signingAppUuid.ToHyphenString()}.json",
                StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound) { RequestMessage = request };
            }

            bool isProtocolSuiteTest = request.RequestUri.AbsolutePath.Contains(
                _signingAppUuid.ToHyphenString());

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(
                    JsonConvert.SerializeObject(new
                    {
                        security_token = new ApplicationInfo()
                        {
                            Uuid = isProtocolSuiteTest ? _signingAppUuid : _clientUuid,
                            Name = "Medidata.MAuth.Tests",
                            CreationDate = new DateTimeOffset(2016, 8, 1, 0, 0, 0, TimeSpan.Zero),
                            PublicKey = isProtocolSuiteTest ? _signingPublicKey : TestExtensions.ClientPublicKey
                        }
                    })
                )
            };
        }
    }
}
