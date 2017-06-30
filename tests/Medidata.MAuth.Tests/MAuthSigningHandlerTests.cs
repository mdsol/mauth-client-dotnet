using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthSigningHandlerTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task SendAsync_WithValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await TestData.For(method);
            var actual = new AssertSigningHandler();
            var signingHandler = new MAuthSigningHandler(TestExtensions.ClientOptions(testData.SignedTime), actual);

            // Act
            using (var client = new HttpClient(signingHandler))
            {
                await client.SendAsync(testData.Request);
            }

            // Assert
            Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
            Assert.Equal(testData.SignedTime, actual.MAuthTimeHeader.FromUnixTimeSeconds());
        }
    }
}
