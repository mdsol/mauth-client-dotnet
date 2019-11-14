using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Owin;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.Owin.Hosting;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthOwinTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthMiddleware_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();

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
                var response = await server.HttpClient.SendAsync(testData.ToDefaultHttpRequestMessage());

                // Assert
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthMiddleware_WithoutMAuthHeader_WillNotAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();

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
        public static async Task MAuthMiddleware_WithEnabledExceptions_WillThrowException(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            using (var server = TestServer.Create(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                    options.HideExceptionsAndReturnUnauthorized = false;
                });

                app.Run(async context => await context.Response.WriteAsync("Done."));
            }))
            {
                // Act, Assert
                var ex = await Assert.ThrowsAsync<AuthenticationException>(
                    () => server.HttpClient.SendAsync(
                        new HttpRequestMessage(testData.Method.ToHttpMethod(), testData.Url)));

                Assert.Equal("The request has invalid MAuth authentication headers.", ex.Message);
                Assert.NotNull(ex.InnerException);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task MAuthMiddleware_WithNonSeekableBodyStream_WillRestoreBodyStream(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var canSeek = false;
            var body = string.Empty;

            using (var server = WebApp.Start("http://localhost:29999/", app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                });

                app.Run(async context =>
                {
                    canSeek = context.Request.Body.CanSeek;
                    body = await new StreamReader(context.Request.Body).ReadToEndAsync();

                    await context.Response.WriteAsync("Done.");
                });
            }))
            {
                // Act
                var response = await new HttpClient().SendAsync(testData.ToDefaultHttpRequestMessage());

                // Assert
                Assert.True(canSeek);
                Assert.Equal(testData.Base64Content.ToStringContent() ?? string.Empty, body);
            }
        }
    }
}
