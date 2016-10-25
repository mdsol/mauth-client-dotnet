using Medidata.MAuth.Core;

namespace Medidata.MAuth.WebApi
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthAuthenticatingHandler"/>.
    /// </summary>
    public class MAuthWebApiOptions: MAuthOptionsBase
    {
         /// <summary>
        /// Determines if the message handler should swallow all exceptions and return an empty HTTP response with a
        /// status code Forbidden (403) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnForbidden { get; set; } = true;
    }
}
