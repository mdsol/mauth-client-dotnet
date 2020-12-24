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
    public static class MAuthCoreTests
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
            var mAuthCore = new MAuthCore();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var result = await mAuthCore.CalculatePayload(testData.ToHttpRequestMessage(), authInfo);

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Fact]
        public static void Verify_WithCorrectlySignedData_WillVerifyTheDataAsValid()
        {
            // Arrange
            var signature = "This is a signature.";
            var unsignedData = Encoding.UTF8.GetBytes(signature);

            var signer = new Pkcs1Encoding(new RsaEngine());
            signer.Init(true, TestExtensions.ClientPrivateKey.AsCipherParameters());

            var signedData = signer.ProcessBlock(unsignedData, 0, unsignedData.Length);

            var mAuthCore = new MAuthCore();

            // Act
            var result = mAuthCore.Verify(signedData, unsignedData, TestExtensions.ClientPublicKey);

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
            var mAuthCore = new MAuthCore();

            var expectedSignature =
                ($"{testData.Method}\n" +
                 $"{testData.Url.AbsolutePath}\n" +
                 $"{testData.Base64Content.ToStringContent()}\n" +
                 $"{testData.ApplicationUuidString}\n" +
                 $"{testData.SignedTimeUnixSeconds}")
                .AsSHA512Hash();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime
            };

            // Act
            var result = await mAuthCore.GetSignature(testData.ToHttpRequestMessage(), authInfo);

            // Assert
            Assert.Equal(expectedSignature, result);
        }

        [Fact]
        public static async Task CalculatePayload_WithBinaryContent_WillCalculateTheProperPayload()
        {
            // Arrange
            var testData = await "POSTWithBinaryData".FromResource();
            var mAuthCore = new MAuthCore();

            // Act
            var result = await mAuthCore.CalculatePayload(testData.ToHttpRequestMessage(), new PrivateKeyAuthenticationInfo()
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
        public static async Task AddAuthenticationInfo_WithRequestAndAuthInfo_WillAddCorrectInformation(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var expectedMAuthHeader = testData.MAuthHeader;
            var mAuthCore = new MAuthCore();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var actual = await mAuthCore.AddAuthenticationInfo(testData.ToHttpRequestMessage(), authInfo);

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
            var exception = Record.Exception(() => keyPath.Inflate().AsCipherParameters());

            // Assert
            Assert.Null(exception);
        }

        [Theory]
        [InlineData("LinuxLineEnding.pem")]
        [InlineData("WindowsLineEnding.pem")]
        [InlineData("NoLineEnding.pem")]
        public static void MAuthSigningOptions_InflatesPrivateKey_OnSet(string keyFilename)
        {
            // Arrange
            var expectedPrivateKeyContents = keyFilename.Inflate();

            // Act
            var signingOptions = new MAuthSigningOptions { PrivateKey = keyFilename };

            // Assert
            Assert.Equal(expectedPrivateKeyContents, signingOptions.PrivateKey);
        }
    }
}
