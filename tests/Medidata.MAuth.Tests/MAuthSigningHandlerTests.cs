using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
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
        public static async Task SendAsync_WithValidRequest_WillSignProperly(string method)
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
    }
}
