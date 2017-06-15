using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthCoreExtensionsTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task CalculatePayload_WithRequestAndAuthInfo_WillReturnCorrectPayload(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var result = await testData.Request.CalculatePayload(authInfo);

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Fact]
        public async Task Verify_WithCorrectlySignedData_WillVerifyTheDataAsValid()
        {
            // Arrange
            var signature = "This is a signature.";
            var unsignedData = Encoding.UTF8.GetBytes(signature);

            var signer = new Pkcs1Encoding(new RsaEngine());
            signer.Init(true, TestExtensions.ClientPrivateKey.AsCipherParameters());

            var signedData = signer.ProcessBlock(unsignedData, 0, unsignedData.Length);

            // Act
            var result = await signedData.Verify(Encoding.UTF8.GetBytes(signature), TestExtensions.ClientPublicKey);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task GetSignature_WithRequest_WillReturnTheCorrectSignature(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            var expectedSignature =
                ($"{method}\n/\n{testData.Content}\n{TestExtensions.ClientUuid.ToHyphenString()}\n" +
                 $"{testData.SignedTime.ToUnixTimeSeconds()}")
                .AsSHA512Hash();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
                SignedTime = testData.SignedTime
            };

            // Act
            var result = await testData.Request.GetSignature(authInfo);

            // Assert
            Assert.Equal(expectedSignature, result);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task GetAuthenticationInfo_WithSignedRequest_WillReturnCorrectAuthInfo(string method)
        {
            // Arrange
            var testData = await TestData.For(method);
            var request = new HttpRequestMessage(testData.Method, TestExtensions.TestUri);

            request.Headers.Add(
                Constants.MAuthHeaderKey, $"MWS {TestExtensions.ClientUuid.ToHyphenString()}:{testData.Payload}");
            request.Headers.Add(Constants.MAuthTimeHeaderKey, testData.SignedTimeUnixSeconds.ToString());

            // Act
            var actual = request.GetAuthenticationInfo();

            // Assert
            Assert.Equal(TestExtensions.ClientUuid, actual.ApplicationUuid);
            Assert.Equal(Convert.FromBase64String(testData.Payload), actual.Payload);
            Assert.Equal(testData.SignedTime, actual.SignedTime);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task AddAuthenticationInfo_WithRequestAndAuthInfo_WillAddCorrectInformation(string method)
        {
            // Arrange
            var testData = await TestData.For(method);
            var expectedMAuthHeader = $"MWS {TestExtensions.ClientUuid.ToHyphenString()}:{testData.Payload}";

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var actual = await testData.Request.AddAuthenticationInfo(authInfo);

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey));
            Assert.Equal(
                authInfo.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey)
            );
        }

        [Theory]
        [InlineData("LinuxLineEnding.pem")]
        [InlineData("WindowsLineEnding.pem")]
        [InlineData("NoLineEnding.pem")]
        public void AsCipherParameters_WithDifferentLineEndingKeys_WillReadTheKeysSuccessfully(string keyFilename)
        {
            // Arrange
            var keyPath = $"Mocks\\Keys\\{keyFilename}";

            // Act
            var exception = Record.Exception(() => keyPath.Dereference().NormalizeLines().AsCipherParameters());

            // Assert
            Assert.Null(exception);
        }
    }
}
