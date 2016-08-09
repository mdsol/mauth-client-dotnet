﻿using System;
using Medidata.MAuth.Core;
using Microsoft.Owin;

namespace Medidata.MAuth.Owin
{
    /// <summary>
    /// Contains the options used by the <see cref="MAuthMiddleware"/>.
    /// </summary>
    public class MAuthMiddlewareOptions: MAuthOptions
    {
         /// <summary>
        /// Determines if the middleware should swallow all exceptions and return an empty HTTP response with a
        /// status code Forbidden (403) in case of any errors (including authentication and validation errors).
        /// The default is <see langword="true"/>.
        /// </summary>
        public bool HideExceptionsAndReturnForbidden { get; set; } = true;

        /// <summary>
        /// Determines a function which evaluates if a given request should bypass the MAuth authentication.
        /// </summary>
        /// <remarks>
        /// The function takes a <see cref="IOwinRequest"/> and should produce <see langword="true"/> as a result,
        /// if the given request satisfies the conditions to bypass the authentication; otherwise it should result
        /// <see langword="false"/> therefore an authentication attempt will occur. If no Bypass predicate provided in
        /// the options, every request will be authenticated by default.
        /// </remarks>
        public Func<IOwinRequest, bool> Bypass { get; set; } = (request) => false;
    }
}
