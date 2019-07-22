using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
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
            var mAuthCore = MAuthCoreImplementation.MAuthCore;

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
            var mAuthCore = MAuthCoreImplementation.MAuthCore;

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
        public static async Task AuthenticateRequest_AfterNumberOfAttempts_WillThrowExceptionWithRequestFailure(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await "GET".FromResource();

            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: false));
            var mAuthCore = MAuthCoreImplementation.MAuthCore;

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
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public static async Task SignRequest_WithValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await method.FromResource();
            var expectedMAuthHeader = testData.MAuthHeader;
            var mAuthCore = MAuthCoreImplementation.MAuthCore;

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
        public static async Task GetAuthenticationInfo_WithSignedRequest_WillReturnCorrectAuthInfo(string method)
        {
            // Arrange
            var authenticator = new MAuthAuthenticator(TestExtensions.ServerOptions);
            var testData = await method.FromResource();
            var request = new HttpRequestMessage(new HttpMethod(testData.Method), TestExtensions.TestUri);

            request.Headers.Add(
                Constants.MAuthHeaderKey, testData.MAuthHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKey, testData.SignedTimeUnixSeconds.ToString());

            // Act
            var actual = authenticator.GetAuthenticationInfo(request);

            // Assert
            Assert.Equal(testData.ApplicationUuid, actual.ApplicationUuid);
            Assert.Equal(Convert.FromBase64String(testData.Payload), actual.Payload);
            Assert.Equal(testData.SignedTime, actual.SignedTime);
        }
    }
}
