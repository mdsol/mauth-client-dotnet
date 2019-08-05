using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Exceptions;
using Medidata.MAuth.Core.Models;
using Medidata.MAuth.Tests.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthSigningHandlerTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithValidMWSRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var actual = new AssertSigningHandler();
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage());
            }

            // Assert
            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, actual.MAuthTimeHeader.FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithValidMWSV2Request_WillSignProperly(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var version = MAuthVersion.MWSV2;
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.MAuthVersion = MAuthVersion.MWSV2;
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);
           
            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, actual.MAuthTimeHeader.FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithMWSRequest_WithDisableV1_WillThrowInvalidVersionException(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.DisableV1 = true;
            clientOptions.MAuthVersion = MAuthVersion.MWS;
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);

            // Act, Assert
            using (var client = new HttpClient(signingHandler))
            {
                var exception = (await Assert.ThrowsAsync<InvalidVersionException>(
                    () => client.SendAsync(testData.ToHttpRequestMessage())));
            }
        }
    }
}
