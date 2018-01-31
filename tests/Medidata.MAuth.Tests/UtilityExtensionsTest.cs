using System;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class UtilityExtensionsTest
    {
        [Fact]
        public async Task TryParseAuthenticationHeader_WithValidAuthHeader_WillSucceed()
        {
            // Arrange
            var request = await TestData.For("GET");
            var expected = (TestExtensions.ClientUuid, request.Payload);

            // Act
            var result = request.MAuthHeader.TryParseAuthenticationHeader(out var actual);

            // Assert
            Assert.True(result);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void TryParseAuthenticationHeader_WithInvalidAuthHeader_WillFail()
        {
            // Arrange
            var invalid = "invalid";

            // Act
            var result = invalid.TryParseAuthenticationHeader(out var actual);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task TryParseAuthenticationHeader_WithVersion1Uuid_WillSucceed()
        {
            // Arrange
            var uuid = "1ebab21a-4b86-11e1-bcfe-123138140309";
            var request = await TestData.For("GET");

            var expected = (new Guid(uuid), request.Payload);

            // Act
            var result = request.MAuthHeader.Replace(TestExtensions.ClientUuid.ToString(), uuid)
                .TryParseAuthenticationHeader(out var actual);

            // Assert
            Assert.True(result);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ParseAuthenticationHeader_WithInvalidAuthHeader_WillThrowException()
        {
            // Arrange
            var invalid = "invalid";

            // Act, Assert
            Assert.Throws<ArgumentException>(() => invalid.ParseAuthenticationHeader());
        }
    }
}
