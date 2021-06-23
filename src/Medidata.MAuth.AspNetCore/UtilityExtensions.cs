using Microsoft.AspNetCore.Http;
using Medidata.MAuth.Core;

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
            var requestMessage = request.ToHttpRequestMessage();

            return requestMessage.GetAuthHeaderValue();
        }
    }
}
