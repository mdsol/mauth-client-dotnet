using System.IO;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.AspNetCore;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthAspNetCoreTests
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthMiddleware_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            using (var server = new TestServer(new WebHostBuilder().Configure(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                    options.HideExceptionsAndReturnUnauthorized = false;
                });

                app.Run(async context => await new StreamWriter(context.Response.Body).WriteAsync("Done."));
            })))
            {
                // Act
                var response = await server.CreateClient().SendAsync(
                    await testData.ToHttpRequestMessage().Sign(TestExtensions.ClientOptions(testData.SignedTime)));

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
            var testData = await method.FromResource();

            using (var server = new TestServer(new WebHostBuilder().Configure(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                });

                app.Run(async context => await new StreamWriter(context.Response.Body).WriteAsync("Done."));
            })))
            {
                // Act
                var response = await server.CreateClient().SendAsync(testData.ToHttpRequestMessage());

                // Assert
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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
            var testData = await method.FromResource();

            using (var server = new TestServer(new WebHostBuilder().Configure(app =>
            {
                app.UseMAuthAuthentication(options =>
                {
                    options.ApplicationUuid = TestExtensions.ServerUuid;
                    options.MAuthServiceUrl = TestExtensions.TestUri;
                    options.PrivateKey = TestExtensions.ServerPrivateKey;
                    options.MAuthServerHandler = new MAuthServerHandler();
                    options.HideExceptionsAndReturnUnauthorized = false;
                });
            })))
            {
                // Act, Assert
                var ex = await Assert.ThrowsAsync<AuthenticationException>(
                    () => server.CreateClient().SendAsync(testData.ToHttpRequestMessage()));

                Assert.Equal("The request has invalid MAuth authentication headers.", ex.Message);
                Assert.NotNull(ex.InnerException);
            }
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task MAuthMiddleware_WithNonSeekableBodyStream_WillRestoreBodyStream(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var canSeek = false;
            var body = string.Empty;
            using (var server = new TestServer(new WebHostBuilder().Configure(app =>
            {
                app
                    .UseMiddleware<RequestBodyAsNonSeekableMiddleware>()
                    .UseMAuthAuthentication(options =>
                    {
                        options.ApplicationUuid = TestExtensions.ServerUuid;
                        options.MAuthServiceUrl = TestExtensions.TestUri;
                        options.PrivateKey = TestExtensions.ServerPrivateKey;
                        options.MAuthServerHandler = new MAuthServerHandler();
                    })
                    .Run(async context =>
                    {
                        canSeek = context.Request.Body.CanSeek;
                        context.Request.Body.Seek(0, SeekOrigin.Begin);
                        body = await new StreamReader(context.Request.Body).ReadToEndAsync();
                    });
            })))
            {
                // Act
                var response = await server.CreateClient().SendAsync(
                    await testData.ToHttpRequestMessage().Sign(TestExtensions.ClientOptions(testData.SignedTime)));

                // Assert
                Assert.True(canSeek);
                Assert.Equal(testData.Base64Content.ToStringContent() ?? string.Empty, body);
            }
        }
    }
}
