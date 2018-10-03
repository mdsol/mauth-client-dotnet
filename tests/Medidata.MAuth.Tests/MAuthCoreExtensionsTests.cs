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
    public static class MAuthCoreExtensionsTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task CalculatePayload_WithRequestAndAuthInfo_WillReturnCorrectPayload(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var result = await testData.ToHttpRequestMessage().CalculatePayload(authInfo);

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Fact]
        public static async Task Verify_WithCorrectlySignedData_WillVerifyTheDataAsValid()
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
        public static async Task GetSignature_WithRequest_WillReturnTheCorrectSignature(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            var expectedSignature =
                ($"{method}\n/\n{testData.Base64Content.ToStringContent()}\n" +
                 $"{testData.ApplicationUuidString}\n" +
                 $"{testData.SignedTime.ToUnixTimeSeconds()}")
                .AsSHA512Hash();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime
            };

            // Act
            var result = await testData.ToHttpRequestMessage().GetSignature(authInfo);

            // Assert
            Assert.Equal(expectedSignature, result);
        }

        [Fact]
        public static async Task CalculatePayload_WithBinaryContent_WillCalculateTheProperPayload()
        {
            // Arrange
            var testData = await "POSTWithBinaryData".FromResource();

            // Act
            var result = await testData.ToHttpRequestMessage().CalculatePayload(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            });

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task GetAuthenticationInfo_WithSignedRequest_WillReturnCorrectAuthInfo(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var request = new HttpRequestMessage(new HttpMethod(testData.Method), TestExtensions.TestUri);

            request.Headers.Add(
                Constants.MAuthHeaderKey, testData.MAuthHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKey, testData.SignedTimeUnixSeconds.ToString());

            // Act
            var actual = request.GetAuthenticationInfo();

            // Assert
            Assert.Equal(testData.ApplicationUuid, actual.ApplicationUuid);
            Assert.Equal(Convert.FromBase64String(testData.Payload), actual.Payload);
            Assert.Equal(testData.SignedTime, actual.SignedTime);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AddAuthenticationInfo_WithRequestAndAuthInfo_WillAddCorrectInformation(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var expectedMAuthHeader = testData.MAuthHeader;

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var actual = await testData.ToHttpRequestMessage().AddAuthenticationInfo(authInfo);

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
        public static void AsCipherParameters_WithDifferentLineEnding_WillReadTheKeysSuccessfully(string keyFilename)
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
