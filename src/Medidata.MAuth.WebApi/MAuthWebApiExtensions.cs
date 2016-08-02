using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.WebApi
{
    internal static class MAuthWebApiExtensions
    {
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
