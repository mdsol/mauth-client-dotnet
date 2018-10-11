using System.Collections.Generic;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.HttpModule
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticationModule"/>.
    /// </summary>
    public class MAuthAuthenticationModuleOptions : MAuthOptionsBase
    {
        /// <summary>
        /// Determines if the httpmodule should swallow all exceptions and return an empty HTTP response with a
        /// status code Unauthorized (401) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnUnauthorized { get; set; } = true;

        /// <summary>
        /// List of paths that will be exempted for MAuth authentication process.
        /// </summary>
        public IEnumerable<string> MAuthExceptionPaths { get; set; }
    }
}
