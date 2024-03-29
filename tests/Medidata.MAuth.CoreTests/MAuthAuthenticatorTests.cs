﻿using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Exceptions;
using Medidata.MAuth.Core.Models;
using Medidata.MAuth.Tests.Common.Infrastructure;
using Medidata.MAuth.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthAuthenticatorTests
    {
        [Theory]
        [InlineData(null, "private key")]
        [InlineData("http://localhost", null)]
        public static void MAuthAuthenticator_WithInvalidOptions_WillThrowException(
            string mauthServiceUrl, string privateKey) =>
            Assert.Throws<ArgumentNullException>(() => new MAuthAuthenticator(new MAuthTestOptions()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
                MAuthServiceUrl = mauthServiceUrl != null ? new Uri(mauthServiceUrl) : null,
                PrivateKey = privateKey
            }, NullLogger<MAuthAuthenticator>.Instance));

        [Fact]
        public static void MAuthAuthenticator_WithDefaultUuid_WillThrowException() =>
            Assert.Throws<ArgumentException>(() => new MAuthAuthenticator(new MAuthTestOptions()
        {
            ApplicationUuid = default(Guid)
        }, NullLogger<MAuthAuthenticator>.Instance));

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithValidMWSRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCore();

            var request = testData.ToHttpRequestMessage(MAuthVersion.MWS);
            var requestContents = await request.GetRequestContentAsBytesAsync();
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.True(isAuthenticated);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithValidMWSV2Request_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var version = MAuthVersion.MWSV2;
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var httpRequestMessage = testData.ToHttpRequestMessage(version);

            var requestContents = await httpRequestMessage.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(httpRequestMessage, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.True(isAuthenticated);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithMWSRequestSignedTooEarly_WillFailToAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime.AddDays(1) };
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCore();

            var request = testData.ToHttpRequestMessage(MAuthVersion.MWS);
            var requestContents = await request.GetRequestContentAsBytesAsync();
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.False(isAuthenticated);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithMWSRequestSignedTooLate_WillFailToAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime.AddDays(-1) };
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCore();

            var request = testData.ToHttpRequestMessage(MAuthVersion.MWS);
            var requestContents = await request.GetRequestContentAsBytesAsync();
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.False(isAuthenticated);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithMWS2RequestSignedTooEarly_AndFallbackDisabled_WillFailToAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime.AddDays(1) };
            var version = MAuthVersion.MWSV2;
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            options.DisableV1 = true;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var httpRequestMessage = testData.ToHttpRequestMessage(version);

            var requestContents = await httpRequestMessage.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(httpRequestMessage, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.False(isAuthenticated);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithMWS2RequestSignedTooLate_AndFallbackDisabled_WillFailToAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime.AddDays(-1) };
            var version = MAuthVersion.MWSV2;
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            options.DisableV1 = true;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var httpRequestMessage = testData.ToHttpRequestMessage(version);

            var requestContents = await httpRequestMessage.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(httpRequestMessage, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.False(isAuthenticated);
        }


        [Theory]
        [InlineData(MAuthServiceRetryPolicy.NoRetry)]
        [InlineData(MAuthServiceRetryPolicy.RetryOnce)]
        [InlineData(MAuthServiceRetryPolicy.RetryTwice)]
        [InlineData(MAuthServiceRetryPolicy.Agressive)]
        public static async Task AuthenticateRequest_WithNumberOfAttempts_WillAuthenticate(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResourceV2();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.GetServerOptionsWithAttempts(policy, shouldSucceedWithin: true, serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };


            var httpRequestMessage = testData.ToDefaultHttpRequestMessage();

            var requestContents = await httpRequestMessage.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(httpRequestMessage, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.True(isAuthenticated);
        }

        [Theory]
        [InlineData(MAuthServiceRetryPolicy.NoRetry)]
        [InlineData(MAuthServiceRetryPolicy.RetryOnce)]
        [InlineData(MAuthServiceRetryPolicy.RetryTwice)]
        [InlineData(MAuthServiceRetryPolicy.Agressive)]
        public static async Task AuthenticateRequest_WithMWSV2Request_WithNumberOfAttempts_WillAuthenticate(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResourceV2();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var version = MAuthVersion.MWSV2;
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.GetServerOptionsWithAttempts(policy, shouldSucceedWithin: true, serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };


            var httpRequestMessage = testData.ToHttpRequestMessage(version);
            var requestContents = await httpRequestMessage.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(httpRequestMessage, authInfo, requestContents);

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(signedRequest);

            // Assert
            Assert.True(isAuthenticated);
        }

        [Theory]
        [InlineData(MAuthServiceRetryPolicy.NoRetry)]
        [InlineData(MAuthServiceRetryPolicy.RetryOnce)]
        [InlineData(MAuthServiceRetryPolicy.RetryTwice)]
        [InlineData(MAuthServiceRetryPolicy.Agressive)]
        public static async Task AuthenticateRequest_AfterNumberOfAttempts_WillThrowExceptionWithRequestFailure(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options =
                TestExtensions.GetServerOptionsWithAttempts(policy, shouldSucceedWithin: false, serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCore();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var request = testData.ToHttpRequestMessage();
            var requestContents = await request.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var exception = (await Assert.ThrowsAsync<AuthenticationException>(
                () => authenticator.AuthenticateRequest(signedRequest)));

            var innerException = exception.InnerException as RetriedRequestException;

            // Assert
            Assert.NotNull(innerException);
            Assert.Equal((int)policy + 1, innerException.Responses.Count);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, innerException.Responses.First().StatusCode);
        }

        [Theory]
        [InlineData(MAuthServiceRetryPolicy.NoRetry)]
        [InlineData(MAuthServiceRetryPolicy.RetryOnce)]
        [InlineData(MAuthServiceRetryPolicy.RetryTwice)]
        [InlineData(MAuthServiceRetryPolicy.Agressive)]
        public static async Task AuthenticateRequest_WithMWSV2Request_AfterNumberOfAttempts_WillThrowExceptionWithRequestFailure(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var version = MAuthVersion.MWSV2;
            var serverHandler = await MAuthServerHandler.CreateAsync();

            var options =
                TestExtensions.GetServerOptionsWithAttempts(policy, shouldSucceedWithin: false, serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCoreV2();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var request = testData.ToHttpRequestMessage(version);
            var requestContents = await request.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var exception = (await Assert.ThrowsAsync<AuthenticationException>(
                () => authenticator.AuthenticateRequest(signedRequest)));

            var innerException = exception.InnerException as RetriedRequestException;

            // Assert
            Assert.NotNull(innerException);
            Assert.Equal((int)policy + 1, innerException.Responses.Count);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, innerException.Responses.First().StatusCode);
        }

 #if NET5_0_OR_GREATER
        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static void SignRequestSync_WithMWSValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = method.FromResourceSync();
            var expectedMAuthHeader = testData.MAuthHeader;
            var mAuthCore = new MAuthCore();

            // Act
            var actual = mAuthCore.SignSync(testData.ToHttpRequestMessage(), TestExtensions.ClientOptions(testData.SignedTime));

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey));
            Assert.Equal(
                testData.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey)
            );
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static void SignRequestSync_WithMWSV2ValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = method.FromResourceV2Sync();
            var version = MAuthVersion.MWSV2;
            var expectedMAuthHeader = testData.MAuthHeaderV2;
            var mAuthCore = new MAuthCoreV2();

            // Act
            var actual = mAuthCore.SignSync(testData.ToHttpRequestMessage(version), TestExtensions.ClientOptions(testData.SignedTime));

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2));
            Assert.Equal(
                testData.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKeyV2)
            );
        }
#endif

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SignRequest_WithMWSValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var expectedMAuthHeader = testData.MAuthHeader;
            var mAuthCore = new MAuthCore();

            // Act
            var actual = await mAuthCore.Sign(testData.ToHttpRequestMessage(),TestExtensions.ClientOptions(testData.SignedTime));

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey));
            Assert.Equal(
                testData.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey)
            );
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SignRequest_WithMWSV2ValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var version = MAuthVersion.MWSV2;
            var expectedMAuthHeader = testData.MAuthHeaderV2;
            var mAuthCore = new MAuthCoreV2();

            // Act
            var actual = await mAuthCore.Sign(testData.ToHttpRequestMessage(version), TestExtensions.ClientOptions(testData.SignedTime));

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2));
            Assert.Equal(
                testData.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKeyV2)
            );
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithMWSVersion_WithDisableV1_WillThrowExceptionWithInvalidVersion(
            string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var testOptions = TestExtensions.ServerOptions(await MAuthServerHandler.CreateAsync());
            testOptions.DisableV1 = true;
            testOptions.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(testOptions, NullLogger<MAuthAuthenticator>.Instance);
            var mAuthCore = new MAuthCore();

            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = testData.ApplicationUuid,
                PrivateKey = TestExtensions.ClientPrivateKey,
                SignedTime = testData.SignedTime
            };

            var request = testData.ToHttpRequestMessage();

            var requestContents = await request.GetRequestContentAsBytesAsync();
            var signedRequest = mAuthCore
                .AddAuthenticationInfo(request, authInfo, requestContents);

            // Act
            var exception = (await Assert.ThrowsAsync<InvalidVersionException>(
                () => authenticator.AuthenticateRequest(signedRequest)));

            // Assert
            Assert.NotNull(exception);
            Assert.Equal("Authentication with MWS version is disabled.", exception.Message);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task GetAuthenticationInfo_WithSignedRequest_ForMWSV2Version_WillReturnCorrectAuthInfo(string method)
        {
            // Arrange
            var testData = await method.FromResourceV2();
            var version = MAuthVersion.MWSV2;
            var testOptions = TestExtensions.ServerOptions(await MAuthServerHandler.CreateAsync());
            var mAuthCore = MAuthCoreFactory.Instantiate(version);

            // Act
            var actual = MAuthAuthenticator.GetAuthenticationInfo(testData.ToHttpRequestMessage(version), mAuthCore);

            // Assert
            Assert.Equal(testData.ApplicationUuid, actual.ApplicationUuid);
            Assert.Equal(Convert.FromBase64String(testData.Payload), actual.Payload);
            Assert.Equal(testData.SignedTime, actual.SignedTime);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task GetAuthenticationInfo_WithSignedRequest_ForMWSVersion_WillReturnCorrectAuthInfo(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var version = MAuthVersion.MWS;
            var testOptions = TestExtensions.ServerOptions(await MAuthServerHandler.CreateAsync());
            var mAuthCore = MAuthCoreFactory.Instantiate(version);

            // Act
            var actual = MAuthAuthenticator.GetAuthenticationInfo(testData.ToHttpRequestMessage(version), mAuthCore);

            // Assert
            Assert.Equal(testData.ApplicationUuid, actual.ApplicationUuid);
            Assert.Equal(Convert.FromBase64String(testData.Payload), actual.Payload);
            Assert.Equal(testData.SignedTime, actual.SignedTime);
        }

        [Fact]
        public static async Task AuthenticateRequest_WithDefaultRequest_WhenV2Fails_FallBackToV1AndAuthenticate()
        {
            // Arrange
            var testData = await "GET".FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var mockLogger = new Mock<ILogger>();
            var serverHandler = await MAuthServerHandler.CreateAsync();
            var options = TestExtensions.ServerOptions(serverHandler);
            options.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;
            var authenticator = new MAuthAuthenticator(options, mockLogger.Object);
            var requestData = testData.ToDefaultHttpRequestMessage();

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(requestData);

            // Assert
            Assert.True(isAuthenticated);
        }

        [Fact]
        public static async Task AuthenticateRequest_WithDefaultRequest_AndDisableV1_WhenV2Fails_NotFallBackToV1()
        {
            // Arrange
            var testData = await "GET".FromResource();
            var mockDateTimeOffsetWrapper = new MockDateTimeOffsetWrapper { MockedValue = testData.SignedTime };
            var mockLogger = new Mock<ILogger>();
            var testOptions = TestExtensions.ServerOptions(await MAuthServerHandler.CreateAsync());
            testOptions.DisableV1 = true;
            testOptions.DateTimeOffsetWrapper = mockDateTimeOffsetWrapper;

            var authenticator = new MAuthAuthenticator(testOptions, mockLogger.Object);
            var requestData = testData.ToDefaultHttpRequestMessage();

            // Act
            var isAuthenticated = await authenticator.AuthenticateRequest(requestData);

            // Assert
            Assert.False(isAuthenticated);
        }
    }
}
