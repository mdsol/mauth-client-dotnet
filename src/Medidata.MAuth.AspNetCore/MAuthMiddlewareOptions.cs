using System;
using Medidata.MAuth.Core;
using Microsoft.AspNetCore.Http;

namespace Medidata.MAuth.AspNetCore
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthMiddleware"/>.
    /// </summary>
    public class MAuthMiddlewareOptions : MAuthOptionsBase
    {
        /// <summary>
        /// Determines if the middleware should swallow all exceptions and return an empty HTTP response with a
        /// status code Unauthorized (401) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnUnauthorized { get; set; } = true;

        /// <summary>
        /// Determines a function which evaluates if a given request should bypass the MAuth authentication.
        /// </summary>
        /// <remarks>
        /// The function takes a <see cref="HttpRequest"/> and should produce <see langword="true"/> as a result,
        /// if the given request satisfies the conditions to bypass the authentication; otherwise it should result
        /// <see langword="false"/> therefore an authentication attempt will occur. If no Bypass predicate provided in
        /// the options, every request will be authenticated by default.
        /// </remarks>
        public Func<HttpRequest, bool> Bypass { get; set; } = (request) => false;
    }
}
