using System;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
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
    }
}
