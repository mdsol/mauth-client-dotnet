using System;
using System.Net.Http;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticator"/>.
    /// </summary>
    public class MAuthOptions
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
        /// value will be 10 seconds.
        /// </summary>
        public int AuthenticateRequestTimeoutSeconds { get; set; } = 10;

        /// <summary>
        /// Determines the time when signing requests instead of the current date and time.
        /// This property is for testing purposes only.
        /// </summary>
        internal DateTimeOffset? SignedTime { get; set; }

        /// <summary>
        /// Determines the message handler for the requests to the MAuth server.
        /// This property is for testing purposes only.
        /// </summary>
        internal HttpMessageHandler MAuthServerHandler { get; set; } 
    }
}
