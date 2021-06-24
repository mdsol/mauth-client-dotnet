using Microsoft.AspNetCore.Http;
using Medidata.MAuth.Core;
using System.Linq;
using Microsoft.Extensions.Primitives;

namespace Medidata.MAuth.AspNetCore
{
    /// <summary>
    /// Extensions for AspNetCore objects
    /// </summary>
    public static class UtilityExtensions
    {
        /// <summary>
        /// Determines the correct MAuthHeader value with default check for V2.
        /// Mauth.Core extension doesn't have extension for HttpRequest
        /// </summary>
        /// <param name="request">Aspnet core HttpRequest</param>
        /// <returns>The MAuthHeader value.</returns>
        public static string GetAuthHeaderValue(this HttpRequest request)
        {
            if (request.Headers.TryGetValue(Constants.MAuthHeaderKeyV2, out var authHeaderV2))
            {
                return authHeaderV2;
            }

            request.Headers.TryGetValue(Constants.MAuthHeaderKey, out var authHeaderV1);
            return authHeaderV1;
        }
    }
}
