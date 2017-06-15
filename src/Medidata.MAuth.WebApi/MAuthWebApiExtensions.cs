using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.WebApi
{
    internal static class MAuthWebApiExtensions
    {
        /// <summary>
        /// Attempts to authenticate the provided request in the <see cref="HttpRequestMessage"/> with the provided
        /// authenticator.
        /// </summary>
        /// <param name="request">The request to try to authenticate.</param>
        /// <param name="authenticator">The authenticator which will attempt the request authentication.</param>
        /// <param name="shouldIgnoreExceptions">Determines if any exceptions during the authentication
        /// should be thrown.</param>
        /// <returns>
        /// This method returns <see langword="true"/> if it successfully authenticated the request;
        /// otherwise it will return either <see langword="false"/> if the method should ignore exceptions or
        /// will throw an exception if any errors occurred during the authentication.</returns>
        public static async Task<bool> TryAuthenticate(
            this HttpRequestMessage request, MAuthAuthenticator authenticator, bool shouldIgnoreExceptions)
        {
            try
            {
                return await authenticator.AuthenticateRequest(request);
            }
            catch (Exception)
            {
                if (shouldIgnoreExceptions)
                    return false;

                throw;
            }
        }
    }
}
