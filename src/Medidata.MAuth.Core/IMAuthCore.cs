using System.Net.Http;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core
{
    internal interface IMAuthCore
    {
        Task<HttpRequestMessage> Sign(HttpRequestMessage request, MAuthSigningOptions options);

        bool Verify(byte[] signedData, byte[] signature, string publicKey);

        Task<byte[]> GetSignature(HttpRequestMessage request, AuthenticationInfo authInfo);

        (string mAuthHeaderKey, string mAuthTimeHeaderKey) GetHeaderKeys();
    }
}
