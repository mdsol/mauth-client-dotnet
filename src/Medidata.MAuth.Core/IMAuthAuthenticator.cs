using System.Net.Http;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core;

public interface IMAuthAuthenticator
{
    /// <summary>
    /// Authenticate http request.
    /// </summary>
    /// <param name="request">Http context converted to a http request.</param>
    /// <returns>
    /// This method returns <see langword="true"/> if it successfully authenticated the request  otherwise it will return <see langword="false"/>.
    /// </returns>
    Task<bool> AuthenticateRequest(HttpRequestMessage request);
}