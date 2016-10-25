using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Owin;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;

namespace Medidata.MAuth.Tests
{
    [ExcludeFromCodeCoverage]
    public class MAuthOwinTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthMiddleware_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            using (var server = TestServer.Create(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                });

                app.Run(async context => await context.Response.WriteAsync("Done."));
            }))
            {
                // Act
                var response = await server.HttpClient.SendAsync(
                    await testData.Request.Sign(TestExtensions.ClientOptions(testData.SignedTime)));

                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthMiddleware_WithoutMAuthHeader_WillNotAuthenticate(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            using (var server = TestServer.Create(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                });

                app.Run(async context => await context.Response.WriteAsync("Done."));
            }))
            {
                // Act
                var response = await server.HttpClient.SendAsync(testData.Request);

                // Assert
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthMiddleware_WithEnabledExceptions_WillThrowException(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            using (var server = TestServer.Create(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                    options.HideExceptionsAndReturnForbidden = false;
                });

                app.Run(async context => await context.Response.WriteAsync("Done."));
            }))
            {
                // Act, Assert
                var ex = await Assert.ThrowsAsync<AuthenticationException>(
                    () => server.HttpClient.SendAsync(testData.Request));

                Assert.Equal("The request has invalid MAuth authentication headers.", ex.Message);
                Assert.NotNull(ex.InnerException);
            }
        }
    }
}
