using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Medidata.MAuth.WebApi;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthWebApiTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthAuthenticatingHandler_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await TestData.For(method);
            var actual = new AssertSigningHandler();

            var handler = new MAuthAuthenticatingHandler(new MAuthWebApiOptions()
            {
                ApplicationUuid = TestExtensions.ServerUuid,
                MAuthServiceUrl = TestExtensions.TestUri,
                PrivateKey = TestExtensions.ServerPrivateKey,
                MAuthServerHandler = new MAuthServerHandler()
            }, actual);

            using (var server = new HttpClient(handler))
            {
                // Act
                var response = await server.SendAsync(
                    await testData.Request.Sign(TestExtensions.ClientOptions(testData.SignedTime)));

                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
                Assert.Equal(testData.SignedTime, actual.MAuthTimeHeader.FromUnixTimeSeconds());
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthAuthenticatingHandler_WithoutMAuthHeader_WillNotAuthenticate(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            var handler = new MAuthAuthenticatingHandler(new MAuthWebApiOptions()
            {
                ApplicationUuid = TestExtensions.ServerUuid,
                MAuthServiceUrl = TestExtensions.TestUri,
                PrivateKey = TestExtensions.ServerPrivateKey,
                MAuthServerHandler = new MAuthServerHandler()
            });

            using (var server = new HttpClient(handler))
            {
                // Act
                var response = await server.SendAsync(testData.Request);

                // Assert
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthAuthenticatingHandler_WithEnabledExceptions_WillThrowException(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            var handler = new MAuthAuthenticatingHandler(new MAuthWebApiOptions()
            {
                ApplicationUuid = TestExtensions.ServerUuid,
                MAuthServiceUrl = TestExtensions.TestUri,
                PrivateKey = TestExtensions.ServerPrivateKey,
                MAuthServerHandler = new MAuthServerHandler(),
                HideExceptionsAndReturnForbidden = false
            });

            using (var server = new HttpClient(handler))
            {
                // Act, Assert
                var ex = await Assert.ThrowsAsync<AuthenticationException>(
                    () => server.SendAsync(testData.Request));

                Assert.Equal("The request has invalid MAuth authentication headers.", ex.Message);
                Assert.NotNull(ex.InnerException);
            }
        }
    }
}
