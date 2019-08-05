using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Exceptions;
using Medidata.MAuth.Tests.Infrastructure;
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
            }));

        [Fact]
        public static void MAuthAuthenticator_WithDefaultUuid_WillThrowException() =>
            Assert.Throws<ArgumentException>(() => new MAuthAuthenticator(new MAuthTestOptions()
        {
            ApplicationUuid = default(Guid)
        }));

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task AuthenticateRequest_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await method.FromResource();

            var authenticator = new MAuthAuthenticator(TestExtensions.ServerOptions);
            var mAuthCore = new MAuthCore();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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
            var version = "MWSV2";
            var authenticator = new MAuthAuthenticator(TestExtensions.ServerOptions);
            var mAuthCore = new MAuthCoreV2();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(version), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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
        public static async Task AuthenticateRequest_WithNumberOfAttempts_WillAuthenticate(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResource();

            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: true));
            var mAuthCore = new MAuthCore();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(),new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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
            var version = "MWSV2";
            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: true));
            var mAuthCore = new MAuthCoreV2();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(version), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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

            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: false));
            var mAuthCore = new MAuthCore();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(),new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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
            var version = "MWSV2";
            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: false));
            var mAuthCore = new MAuthCoreV2();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(version), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

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
            var version = "MWSV2";
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
            var testOptions = TestExtensions.ServerOptions;
            testOptions.DisableV1 = true;
            var authenticator = new MAuthAuthenticator(testOptions);
            var mAuthCore = new MAuthCore();

            var signedRequest = await mAuthCore
                .AddAuthenticationInfo(testData.ToHttpRequestMessage(), new PrivateKeyAuthenticationInfo()
                {
                    ApplicationUuid = testData.ApplicationUuid,
                    PrivateKey = TestExtensions.ClientPrivateKey,
                    SignedTime = testData.SignedTime
                });

            // Act
            var exception = (await Assert.ThrowsAsync<InvalidVersionException>(
                () => authenticator.AuthenticateRequest(signedRequest)));

            // Assert
            Assert.NotNull(exception);
            Assert.Equal("Authentication with MWS version is disabled.", exception.Message);
        }
    }
}
