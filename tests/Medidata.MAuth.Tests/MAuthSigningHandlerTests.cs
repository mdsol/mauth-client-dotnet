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
        public static async Task SendAsync_WithNoSigningOptions_WillSignWithOnlyMWSV2(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var actual = new AssertSigningHandler();
            var version = MAuthVersion.MWSV2;
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Null(actual.MAuthHeader);
            Assert.Null(actual.MAuthTimeHeader);

            Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeaderV2);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeaderV2).FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithSigningOptionsV1_WillSignWithMWS(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.SignVersions = "v1";
            var version = MAuthVersion.MWS;
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());

            Assert.Null(actual.MAuthHeaderV2);
            Assert.Null(actual.MAuthTimeHeaderV2);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithSigningOptionsV1AndV2_WillSignWithBothMWSAndMWSV2(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.SignVersions = "v1,v2";
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToDefaultHttpRequestMessage());
            }

            // Assert
            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());

            Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeaderV2);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeaderV2).FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithImproperSigningOptions_WillThrowException(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.SignVersions = "v12";
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);

            // Act
            // Assert
            using (var client = new HttpClient(signingHandler))
            {
                var exception = await Assert.ThrowsAsync<InvalidVersionException>(() 
                    => client.SendAsync(testData.ToDefaultHttpRequestMessage()));
                Assert.Equal(exception.Message, 
                    $"Signing with {clientOptions.SignVersions} version is not allowed.");
            }
        }
    }
}
