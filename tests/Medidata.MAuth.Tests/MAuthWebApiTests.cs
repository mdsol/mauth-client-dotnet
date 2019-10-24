using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;
using Medidata.MAuth.Tests.Infrastructure;
using Medidata.MAuth.WebApi;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthWebApiTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthAuthenticatingHandler_WithValidMWSRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();
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
                var response = await server.SendAsync(testData.ToHttpRequestMessage());

                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(testData.MAuthHeader, actual.MAuthHeader);
                Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeader).FromUnixTimeSeconds());
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthAuthenticatingHandler_WithValidMWSV2Request_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var actual = new AssertSigningHandler();
            var version = MAuthVersion.MWSV2;
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
                var response = await server.SendAsync(testData.ToHttpRequestMessage(version));

                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(testData.MAuthHeaderV2, actual.MAuthHeaderV2);
                Assert.Equal(testData.SignedTime, long.Parse(actual.MAuthTimeHeaderV2).FromUnixTimeSeconds());
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthAuthenticatingHandler_WithoutMAuthHeader_WillNotAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();

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
                var response = await server.SendAsync(
                    new HttpRequestMessage(testData.Method.ToHttpMethod(), testData.Url));

                // Assert
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthAuthenticatingHandler_WithEnabledExceptions_WillThrowException(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            var handler = new MAuthAuthenticatingHandler(new MAuthWebApiOptions()
            {
                ApplicationUuid = TestExtensions.ServerUuid,
                MAuthServiceUrl = TestExtensions.TestUri,
                PrivateKey = TestExtensions.ServerPrivateKey,
                MAuthServerHandler = new MAuthServerHandler(),
                HideExceptionsAndReturnUnauthorized = false
            });

            using (var server = new HttpClient(handler))
            {
                // Act, Assert
                var ex = await Assert.ThrowsAsync<AuthenticationException>(
                    () => server.SendAsync(
                        new HttpRequestMessage(testData.Method.ToHttpMethod(), testData.Url)));

                Assert.Equal("The request has invalid MAuth authentication headers.", ex.Message);
                Assert.NotNull(ex.InnerException);
            }
        }
    }
}
