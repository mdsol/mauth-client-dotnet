using System.Collections.Generic;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.HttpModule
{
    public class MAuthAuthenticationModuleOptions : MAuthOptionsBase
    {
        /// <summary>
        /// Determines if the middleware should swallow all exceptions and return an empty HTTP response with a
        /// status code Unauthorized (401) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnUnauthorized { get; set; } = true;

        /// <summary>
        /// TODO..
        /// </summary>
        public IEnumerable<string> MAuthExceptionPaths { get; set; }
    }
}
