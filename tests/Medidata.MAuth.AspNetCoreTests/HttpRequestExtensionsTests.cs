using System;
using Medidata.MAuth.AspNetCore;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;

namespace Medidata.MAuth.AspNetCoreTests
{
    public class HttpRequestExtensionsTests
    {
        [Fact]
        public void GetAuthHeaderValue_WithNoMauthHeader_WillReturnNull()
        {
            // Arrange
            var headers = new HeaderDictionary();
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.SetupGet(hr => hr.Headers).Returns(headers);
            var httpRequest = mockRequest.Object;

            // Act
            var authHeader = httpRequest.GetAuthHeaderValue();

            // Assert
            Assert.Null(authHeader);
        }

        [Fact]
        public void GetAuthHeaderValue_WithV2Header_WillReturnV2HeaderValue()
        {
            // Arrange
            var headers = new HeaderDictionary();
            headers.Add(Constants.MAuthHeaderKeyV2, "fake v2 mauth header value");
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.SetupGet(hr => hr.Headers).Returns(headers);
            var httpRequest = mockRequest.Object;

            // Act
            var authHeader = httpRequest.GetAuthHeaderValue();

            // Assert
            Assert.Equal("fake v2 mauth header value", authHeader);
        }

        [Fact]
        public void GetAuthHeaderValue_WithV1Header_WillReturnV1HeaderValue()
        {
            // Arrange
            var headers = new HeaderDictionary();
            headers.Add(Constants.MAuthHeaderKey, "v1 header");
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.SetupGet(hr => hr.Headers).Returns(headers);
            var httpRequest = mockRequest.Object;

            // Act
            var authHeader = httpRequest.GetAuthHeaderValue();

            // Assert
            Assert.Equal("v1 header", authHeader);
        }

        [Fact]
        public void GetAppUuid_WithV1Header_WillReturnAppUuid()
        {
            // Arrange
            var requestData = "POST".FromResourceSync();
            var headers = new HeaderDictionary();
            headers.Add(Constants.MAuthHeaderKey, requestData.MAuthHeader);
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.SetupGet(hr => hr.Headers).Returns(headers);
            var httpRequest = mockRequest.Object;

            // Act
            var appUuid = httpRequest.GetAuthAppUuid();

            // Assert
            Assert.Equal(requestData.ApplicationUuid, appUuid);
        }

        [Fact]
        public void GetAppUuid_WithV2Header_WillReturnAppUuid()
        {
            // Arrange
            var requestData = "POST".FromResourceV2Sync();
            var headers = new HeaderDictionary();
            headers.Add(Constants.MAuthHeaderKey, requestData.MAuthHeader);
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.SetupGet(hr => hr.Headers).Returns(headers);
            var httpRequest = mockRequest.Object;

            // Act
            var appUuid = httpRequest.GetAuthAppUuid();

            // Assert
            Assert.Equal(requestData.ApplicationUuid, appUuid);
        }
    }
}
