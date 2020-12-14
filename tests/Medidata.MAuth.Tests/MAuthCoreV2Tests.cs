using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Medidata.MAuth.Tests.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthCoreV2Tests
    {

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task CalculatePayload_WithRequestAndAuthInfo_WillReturnCorrectPayload(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var version = MAuthVersion.MWSV2;
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var result = await mAuthCore.CalculatePayloadAsync(testData.ToHttpRequestMessage(version), authInfo);

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Fact]
        public static async Task CalculatePayload_WithBinaryContent_WillCalculateTheProperPayload()
        {
            // Arrange
            var testData = await "POSTWithBinaryData".FromResourceV2();
            var mAuthCore = new MAuthCoreV2();
            var version = MAuthVersion.MWSV2;
            // Act
            var result = await mAuthCore.CalculatePayloadAsync(testData.ToHttpRequestMessage(version), new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            });

            // Assert
            Assert.Equal(testData.Payload, result);
        }

        [Fact]
        public static void Verify_WithCorrectlySignedData_WillVerifyTheDataAsValid()
        {
            // Arrange
            var signature = "This is a signature.";
            var unsignedData = signature.ToBytes();
            var mAuthCore = new MAuthCoreV2();

            var signer = new RSACryptoServiceProvider();
            signer.PersistKeyInCsp = false;
            signer.ImportParameters(TestExtensions.ClientPrivateKey.AsRsaParameters());
            var signedData = signer.SignData(unsignedData, CryptoConfig.MapNameToOID("SHA512"));

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
            var testData = await method.FromResourceV2();
            var version = MAuthVersion.MWSV2;
            var mAuthCore = new MAuthCoreV2();
            var queryParams = !string.IsNullOrEmpty(testData.Url.Query) ?
                testData.Url.Query.Replace("?","").BuildEncodedQueryParams().ToBytes() :new byte[] { };
            var content = !string.IsNullOrEmpty(testData.Base64Content) ? 
                Convert.FromBase64String(testData.Base64Content)
                : new byte[] { };

            var expectedSignature = new byte[][]
            {
                testData.Method.ToBytes(), Constants.NewLine,
                testData.Url.AbsolutePath.NormalizeUriPath().ToBytes(), Constants.NewLine,
                content.AsSHA512Hash(), Constants.NewLine,
                testData.ApplicationUuidString.ToBytes(), Constants.NewLine,
                testData.SignedTimeUnixSeconds.ToString().ToBytes(), Constants.NewLine,
                queryParams
            }.Concat();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime
            };

            // Act
            var result = await mAuthCore.GetSignatureAsync(testData.ToHttpRequestMessage(version), authInfo);

            // Assert
            Assert.Equal(expectedSignature, result);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AddAuthenticationInfo_WithRequestAndAuthInfo_WillAddCorrectInformation(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var expectedMAuthHeader = testData.MAuthHeaderV2;
            var version = MAuthVersion.MWSV2;
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                SignedTime = testData.SignedTime,
                PrivateKey = TestExtensions.ClientPrivateKey
            };

            // Act
            var actual = await mAuthCore.AddAuthenticationInfoAsync(testData.ToHttpRequestMessage(version), authInfo);

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2));
            Assert.Equal(
                authInfo.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKeyV2)
            );
        }
    }
}
