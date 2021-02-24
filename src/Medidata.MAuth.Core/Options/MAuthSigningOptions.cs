﻿using Medidata.MAuth.Core.Models;
using System;
using System.Collections.Generic;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthSigningHandler"/>.
    /// </summary>
    public class MAuthSigningOptions
    {
        private string _privateKey;

        /// <summary>
        /// Determines the RSA private key for the authentication requests. The value of this property can be set as a
        /// valid path to a readable key file as well.After set, this property will either contain an inflated
        /// private key or `null`.
        /// </summary>
        public string PrivateKey {
            get => _privateKey;
            set => _privateKey = value.Inflate();
        }

        /// <summary>Determines the unique identifier used for the MAuth service authentication requests.</summary>
        public Guid ApplicationUuid { get; set; }

        /// <summary>
        /// Determines the time when signing requests instead of the current date and time.
        /// This property is for testing purposes only.
        /// </summary>
        internal DateTimeOffset? SignedTime { get; set; }

        /// <summary>
        /// Enumeration values of MAuth protocol versions to sign requests, if not provided defaults to `MWS`.
        /// </summary>
        public MAuthVersion SignVersions { get; set; } = MAuthVersion.MWS;
    }
}
