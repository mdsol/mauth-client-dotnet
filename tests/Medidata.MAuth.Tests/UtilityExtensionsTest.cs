using System;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class UtilityExtensionsTest
    {
        [Fact]
        public static async Task TryParseAuthenticationHeader_WithValidAuthHeader_WillSucceed()
        {
            // Arrange
            var request = await "GET".FromResource();
            var expected = (request.ApplicationUuid, request.Payload);

            // Act
            var result = request.MAuthHeader.TryParseAuthenticationHeader(out var actual);

            // Assert
            Assert.True(result);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public static void TryParseAuthenticationHeader_WithInvalidAuthHeader_WillFail()
        {
            // Arrange
            var invalid = "invalid";

            // Act
            var result = invalid.TryParseAuthenticationHeader(out var actual);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public static void ParseAuthenticationHeader_WithInvalidAuthHeader_WillThrowException()
        {
            // Arrange
            var invalid = "invalid";

            // Act, Assert
            Assert.Throws<ArgumentException>(() => invalid.ParseAuthenticationHeader());
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task Authenticate_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            var mAuthCore = new MAuthCore();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

            // Act
            var isAuthenticated = await signedRequest.Authenticate(TestExtensions.ServerOptions, NullLoggerFactory.Instance);

            // Assert
            Assert.True(isAuthenticated);
        }
    }
}
