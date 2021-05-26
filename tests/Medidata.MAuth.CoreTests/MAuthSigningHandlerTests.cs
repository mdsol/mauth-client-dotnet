using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
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
        public static async Task SendAsync_WithNoSignVersions_WillSignWithOnlyMWS(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var actual = new AssertSigningHandler();
            var version = MAuthVersion.MWS;
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Null(actual.MAuthHeaderV2);
            Assert.Null(actual.MAuthTimeHeaderV2);

            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithSignVersionMWS_WillSignWithOnlyMWS(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            var version = MAuthVersion.MWS;
            clientOptions.SignVersions = version;
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
        public static async Task SendAsync_WithSignVersionsMWSAndMWSV2_WillSignWithBothMWSAndMWSV2(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.SignVersions = MAuthVersion.MWS | MAuthVersion.MWSV2;

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

#if NET5_0
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task Send_WithNoSignVersions_WillSignWithOnlyMWS(string method)
        {
            // Arrange
            var testData = method.FromResourceSync();
            var actual = new AssertSigningHandler();
            var version = MAuthVersion.MWS;
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Null(actual.MAuthHeaderV2);
            Assert.Null(actual.MAuthTimeHeaderV2);

            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task Send_WithSignVersionMWS_WillSignWithOnlyMWS(string method)
        {
            // Arrange
            var testData = method.FromResourceV2Sync();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            var version = MAuthVersion.MWS;
            clientOptions.SignVersions = version;
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
        public static async Task Send_WithSignVersionsMWSAndMWSV2_WillSignWithBothMWSAndMWSV2(string method)
        {
            // Arrange
            var testData = method.FromResourceV2Sync();
            var actual = new AssertSigningHandler();
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.SignVersions = MAuthVersion.MWS | MAuthVersion.MWSV2;

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
#endif
    }
}
