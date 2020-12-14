using System.Net.Http;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core
{
    internal interface IMAuthCore
    {
        Task<HttpRequestMessage> SignAsync(HttpRequestMessage request, MAuthSigningOptions options);

        bool Verify(byte[] signedData, byte[] signature, string publicKey);

        Task<byte[]> GetSignatureAsync(HttpRequestMessage request, AuthenticationInfo authInfo);

        (string mAuthHeaderKey, string mAuthTimeHeaderKey) GetHeaderKeys();

#if NET5_0

        HttpRequestMessage Sign(HttpRequestMessage request, MAuthSigningOptions options);
#endif
    }
}
