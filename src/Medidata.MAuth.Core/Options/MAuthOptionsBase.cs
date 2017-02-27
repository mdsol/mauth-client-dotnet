using System;
using System.Net.Http;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticator"/>.
    /// </summary>
    public abstract class MAuthOptionsBase
    {
        /// <summary>Determines the RSA private key for the authentication requests.</summary>
        public string PrivateKey { get; set; }

        /// <summary>Determines the endpoint of the MAuth authentication service.</summary>
        public Uri MAuthServiceUrl { get; set; }

        /// <summary>Determines the unique identifier used for the MAuth service authentication requests.</summary>
        public Guid ApplicationUuid { get; set; }

        /// <summary>
        /// Determines the timeout in seconds for the MAuth authentication request - the MAuth component will try to
        /// reach the MAuth server for this duration before throws an exception. If not specified, the default
        /// value will be 3 seconds.
        /// </summary>
        public int AuthenticateRequestTimeoutSeconds { get; set; } = 3;

        /// <summary>
        /// Determines the number of request retry attempts when communicating with the MAuth authentication service,
        /// and the result is not success. If not specified, the default value will be
        /// <see cref="MAuthServiceRetryPolicy.Normal"/> (2 more attempts additionally for the original request).
        /// </summary>
        public MAuthServiceRetryPolicy MAuthServiceRetryPolicy { get; set; } = MAuthServiceRetryPolicy.Normal;

        /// <summary>
        /// Determines the message handler for the requests to the MAuth server.
        /// This property is for testing purposes only.
        /// </summary>
        internal HttpMessageHandler MAuthServerHandler { get; set; } 
    }
}
