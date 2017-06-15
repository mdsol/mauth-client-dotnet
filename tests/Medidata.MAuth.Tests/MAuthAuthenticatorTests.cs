using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Medidata.MAuth.Tests.Infrastructure;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public class MAuthAuthenticatorTests
    {
        [Theory]
        [InlineData(null, "private key")]
        [InlineData("http://localhost", null)]
        public void MAuthAuthenticator_WithInvalidOptions_WillThrowException(string mauthServiceUrl, string privateKey)
        {
            // Assert
            Assert.Throws<ArgumentNullException>(() => new MAuthAuthenticator(new MAuthTestOptions()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
                MAuthServiceUrl = mauthServiceUrl != null ? new Uri(mauthServiceUrl) : null,
                PrivateKey = privateKey
            }));
        }

        [Fact]
        public void MAuthAuthenticator_WithDefaultUuid_WillThrowException()
        {
            Assert.Throws<ArgumentException>(() => new MAuthAuthenticator(new MAuthTestOptions()
            {
                ApplicationUuid = default(Guid)
            }));
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("DELETE")]
        [InlineData("POST")]
        [InlineData("PUT")]
        public async Task AuthenticateRequest_WithValidRequest_WillAuthenticate(string method)
        {
            // Arrange
            var testData = await TestData.For(method);

            var authenticator = new MAuthAuthenticator(TestExtensions.ServerOptions);

            var signedRequest = await testData.Request.AddAuthenticationInfo(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
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
        public async Task AuthenticateRequest_WithNumberOfAttempts_WillAuthenticate(MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await TestData.For("GET");

            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: true));

            var signedRequest = await testData.Request.AddAuthenticationInfo(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
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
        public async Task AuthenticateRequest_AfterNumberOfAttempts_WillThrowExceptionWithRequestFailure(
            MAuthServiceRetryPolicy policy)
        {
            // Arrange
            var testData = await TestData.For("GET");

            var authenticator = new MAuthAuthenticator(TestExtensions.GetServerOptionsWithAttempts(
                policy, shouldSucceedWithin: false));

            var signedRequest = await testData.Request.AddAuthenticationInfo(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = TestExtensions.ClientUuid,
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
        public async Task SignRequest_WithValidRequest_WillSignProperly(string method)
        {
            // Arrange
            var testData = await TestData.For(method);
            var expectedMAuthHeader = $"MWS {TestExtensions.ClientUuid.ToHyphenString()}:{testData.Payload}";

            // Act
            var actual = await testData.Request.Sign(TestExtensions.ClientOptions(testData.SignedTime));

            // Assert
            Assert.Equal(expectedMAuthHeader, actual.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey));
            Assert.Equal(
                testData.SignedTime.ToUnixTimeSeconds(),
                actual.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey)
            );
        }
    }
}
