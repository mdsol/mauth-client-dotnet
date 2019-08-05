using System;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthSigningHandler"/>.
    /// </summary>
    public class MAuthSigningOptions
    {
        /// <summary>
        /// Determines the RSA private key for the authentication requests. The value of this property can be set as a
        /// valid path to a readable key file as well.</summary>
        public string PrivateKey { get; set; }

        /// <summary>Determines the unique identifier used for the MAuth service authentication requests.</summary>
        public Guid ApplicationUuid { get; set; }

        /// <summary>
        /// Determines the time when signing requests instead of the current date and time.
        /// This property is for testing purposes only.
        /// </summary>
        internal DateTimeOffset? SignedTime { get; set; }

        /// <summary>
        /// Determines the MAuth version for signing requests.
        /// </summary>
        public MAuthVersion MAuthVersion { get; set; }

        /// <summary>
        /// Determines the boolean value if V1 option of signing should be disabled or not with default value of false.
        /// </summary>
        public bool DisableV1 { get; set; } = false;
    }
}
