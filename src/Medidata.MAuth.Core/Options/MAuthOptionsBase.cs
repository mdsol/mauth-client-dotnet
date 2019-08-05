using System;
using System.Net.Http;
using Medidata.MAuth.Core.Models;
using Version = Medidata.MAuth.Core.Models.Version;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticator"/>.
    /// </summary>
    public abstract class MAuthOptionsBase
    {
        /// <summary>
        /// Determines the RSA private key for the authentication requests. The value of this property can be set as a
        /// valid path to a readable key file as well.
        /// </summary>
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
        /// <see cref="MAuthServiceRetryPolicy.RetryOnce"/> (1 more attempt additionally for the original request).
        /// </summary>
        public MAuthServiceRetryPolicy MAuthServiceRetryPolicy { get; set; } = MAuthServiceRetryPolicy.RetryOnce;

        /// <summary>
        /// Determines the message handler for the requests to the MAuth server.
        /// </summary>
        public HttpMessageHandler MAuthServerHandler { get; set; }

        /// <summary>
        /// Determines the boolean value if V1 option of signing should be disabled or not with default value of false.
        /// </summary>
        public bool DisableV1 { get; set; } = false;
    }
}
