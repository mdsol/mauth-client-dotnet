using System;
using Microsoft.AspNetCore.Http;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.AspNetCore
{
    /// <summary>
    /// Extension methods for HttpRequest.
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>
        /// Determines the correct MAuthHeader value with default check for V2.
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <returns>Mauth header value from the request.</returns>
        public static string GetAuthHeaderValue(this HttpRequest request)
        {
            if (request.Headers.TryGetValue(Constants.MAuthHeaderKeyV2, out var authHeaderV2))
            {
                return authHeaderV2;
            }

            request.Headers.TryGetValue(Constants.MAuthHeaderKey, out var authHeaderV1);
            return authHeaderV1;
        }

        /// <summary>
        /// Get app uuid from mauth header value in HttpRequest.
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <returns>application uuid in mauth header value.</returns>
        public static Guid GetAuthAppUuid(this HttpRequest request)
        {
            var mauthHeader = request.GetAuthHeaderValue();
            var (appUuid, _) = mauthHeader.ParseAuthenticationHeader();
            return appUuid;
        }
    }
}
