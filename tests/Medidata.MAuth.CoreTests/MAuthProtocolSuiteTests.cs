using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Medidata.MAuth.Tests.Common.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class MAuthProtocolSuiteTests
    {
        private readonly ProtocolTestSuiteHelper _protcolTestHelper;
        private readonly MAuthCoreV2 _mAuthCore;

        public MAuthProtocolSuiteTests()
        {
            _protcolTestHelper = new ProtocolTestSuiteHelper();
            _mAuthCore = new MAuthCoreV2();
        }

        [Theory, MemberData(nameof(TestCases))]
        [Trait("Category","ProtocolTestSuite")]
        public async Task MAuth_Execute_ProtocolTestSuite(string caseName)
        {
            // Arrange
            var signConfig = await _protcolTestHelper.LoadSigningConfig();
            var requestData = await _protcolTestHelper.LoadUnsignedRequest(caseName);
            var authz = await _protcolTestHelper.ReadAuthenticationHeader(caseName);

            var actual = new AssertSigningHandler();
            var clientOptions = ProtocolTestClientOptions(
                    signConfig.AppUuid, signConfig.PrivateKey, signConfig.RequestTime.FromUnixTimeSeconds());
            clientOptions.SignVersions = MAuthVersion.MWSV2;
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);
            var request = ToHttpRequestMessage(requestData);

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = signConfig.AppUuid,
                SignedTime = signConfig.RequestTime.FromUnixTimeSeconds(),
                PrivateKey = signConfig.PrivateKey
            };

            // Verify Signing and auth headers matches .authz file
            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(request);
            }

            // Assert
            Assert.Equal(authz.MccAuthentication, actual.MAuthHeaderV2);
            Assert.Equal(authz.MccTime, long.Parse(actual.MAuthTimeHeaderV2));

            if (!caseName.StartsWith("authentication-only"))
            {
                var sig = await _protcolTestHelper.ReadDigitalSignature(caseName);

                // Verify payload matches digital signature
                // Act
                var requestContents = await request.GetRequestContentAsBytesAsync();

                var actualPayload = _mAuthCore.CalculatePayload(request, authInfo, requestContents);

                // Assert
                Assert.Equal(sig, actualPayload);

                // Verify string_to_sign is matched
                // Act 
                var result = await _mAuthCore.GetSignature(request, authInfo);
                var sts = await _protcolTestHelper.ReadStringToSign(caseName);

                // Assert
                Assert.Equal(sts, Encoding.UTF8.GetString(result));
            }
            else
            {
                var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = signConfig.RequestTime.FromUnixTimeSeconds() };
                var serverOptions = TestExtensions.ServerOptions(await MAuthServerHandler.CreateAsync());
                serverOptions.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
                var authenticator = new MAuthAuthenticator(serverOptions, NullLogger<MAuthAuthenticator>.Instance);

                var privateKeyAuthenticationInfo = new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = signConfig.AppUuid,
                    PrivateKey = signConfig.PrivateKey,
                    SignedTime = signConfig.RequestTime.FromUnixTimeSeconds()
                };

                var requestContents = await request.GetRequestContentAsBytesAsync();
                var signedRequest = _mAuthCore
                    .AddAuthenticationInfo(request, privateKeyAuthenticationInfo, requestContents);

                // Act
                var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

                // Assert
                Assert.True(isAuthenticated);
            }
        }

        public static IEnumerable<object[]> TestCases =>
            new ProtocolTestSuiteHelper().GetTestCases()
            .Select(tc => new object[] { tc });

        private static MAuthSigningOptions ProtocolTestClientOptions(Guid clientUuid,
            string clientPrivateKey, DateTimeOffset signedTime) => new MAuthSigningOptions()
            {
                ApplicationUuid = clientUuid,
                PrivateKey = clientPrivateKey,
                SignedTime = signedTime
            };

        private static HttpRequestMessage ToHttpRequestMessage(UnSignedRequest data)
        {
            var result = new HttpRequestMessage(new HttpMethod(data.Verb), new Uri($"https://example.com{data.Url}"))
            {
                Content = !string.IsNullOrEmpty(data.Body)
                    ? new ByteArrayContent(Convert.FromBase64String(data.Body)) : null,
            };

            return result;
        }
    }
}
