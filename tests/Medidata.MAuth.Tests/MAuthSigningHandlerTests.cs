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
        public static async Task SendAsync_WithDefault_WillSignProperly_BothMWSAndMWSV2(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var actual = new AssertSigningHandler();
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToDefaultHttpRequestMessage());
            }

            // Assert
            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());

            Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeaderV2);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SendAsync_WithDisableV1_WillSignProperlyWithMWSV2(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var version = MAuthVersion.MWSV2;
            var clientOptions = TestExtensions.ClientOptions(testData.SignedTime);
            clientOptions.DisableV1 = true;
            var signingHandler = new MAuthSigningHandler(clientOptions, actual);


            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.ToHttpRequestMessage(version));
            }

            // Assert
            Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeaderV2);
            Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeaderV2).FromUnixTimeSeconds());
        }
    }
}
