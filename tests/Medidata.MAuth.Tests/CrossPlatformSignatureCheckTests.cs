using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Newtonsoft.Json;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class CrossPlatformSignatureCheckTests
    {
        [Fact]
        public async Task SignatureIsValid_ForV1_WithBinaryContent()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            HttpRequestMessage request = CreateRequest(testData);
            request.Content = new ByteArrayContent(GetBinaryFileBody());

            // Act
            var result = await new MAuthCore().CalculatePayload(request, authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v1_binary"].ToString();

            Assert.Equal(expectedResult, result.ToString());
        }

        [Fact]
        public async Task Signature_IsValidForV1_WithNullContent()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            HttpRequestMessage request = CreateRequest(testData);
            request.Content = null;

            // Act
            var result = await new MAuthCore().CalculatePayload(request, authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v1_empty"].ToString();

            Assert.Equal(expectedResult, result.ToString());
        }

        [Fact]
        public async Task SignatureIsValid_ForV2_WithBinaryContent()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            HttpRequestMessage request = CreateRequest(testData);
            request.Content = new ByteArrayContent(GetBinaryFileBody());

            // Act
            var result = await new MAuthCoreV2().CalculatePayload(request, authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v2_binary"].ToString();

            Assert.Equal(expectedResult, result.ToString());
        }

        [Fact]
        public async Task Signature_IsValidForV2_WithNullContent()
        {
            // Arrange
            var testData = ReadCrossPlatformSignatureValues();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = new Guid(testData["attributes_for_signing"]["app_uuid"].ToString()),
                SignedTime = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(testData["attributes_for_signing"]["time"])),
                PrivateKey = testData["private_key"].ToString()
            };

            HttpRequestMessage request = CreateRequest(testData);
            request.Content = null;

            // Act
            var result = await new MAuthCoreV2().CalculatePayload(request, authInfo);

            // Assert
            var expectedResult = testData["signatures"]["v2_empty"].ToString();

            Assert.Equal(expectedResult, result.ToString());
        }

        private HttpRequestMessage CreateRequest(dynamic testData)
        {
            var requestUri = testData["attributes_for_signing"]["request_url"].ToString();

           return new HttpRequestMessage(new HttpMethod(
                testData["attributes_for_signing"]["verb"].ToString()), new Uri(requestUri)) {};
        }


        private static dynamic ReadCrossPlatformSignatureValues()
        {
            return JsonConvert.DeserializeObject(
                File.ReadAllText(@"Mocks/Fixtures/mauth_signature_testing.json"));
        }

        private static byte[] GetBinaryFileBody()
        {
            var binaryFileData = File.ReadAllBytes(@"Mocks/Fixtures/blank.jpeg");
            return binaryFileData;
        }

    }
}
