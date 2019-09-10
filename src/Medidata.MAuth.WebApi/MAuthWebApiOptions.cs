using Medidata.MAuth.Core;
using Microsoft.Extensions.Logging;

namespace Medidata.MAuth.WebApi
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticatingHandler"/>.
    /// </summary>
    public class MAuthWebApiOptions: MAuthOptionsBase
    {
        /// <summary>
        /// Determines if the message handler should swallow all exceptions and return an empty HTTP response with a
        /// status code Unauthorized (401) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnUnauthorized { get; set; } = true;

        /// <summary>
        /// 
        /// </summary>
        public ILoggerFactory LoggerFactory { get; set; }
    }
}
