using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    internal class MAuthCoreV2 : IMAuthCore
    {
        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="options">The options that contains the required information for the signing.</param>
        /// <returns>
        /// A Task object which will result the request signed with the authentication information when it completes.
        /// </returns>
        public async Task<HttpRequestMessage> Sign(
            HttpRequestMessage request, MAuthSigningOptions options)
        {
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey.Dereference().NormalizeLines()
            };

            var requestContents = await request.GetRequestContentAsBytesAsync().ConfigureAwait(false);
            return AddAuthenticationInfo(request, authInfo, requestContents);
        }

        /// <summary>
        /// Verifies that the signed data is equal to the signature by using the public key of the keypair which
        /// was used to sign the data.
        /// </summary>
        /// <param name="signedData">The data in its signed form.</param>
        /// <param name="signature">The signature which the signed data generated from.</param>
        /// <param name="publicKey">The public key used to decrypt the signed data.</param>
        /// <returns>
        /// If the signed data matches the signature, it returns <see langword="true"/>; otherwise it
        /// returns <see langword="false"/>.
        /// </returns>
        public bool Verify(byte[] signedData, byte[] signature, string publicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.PersistKeyInCsp = false;
            rsa.ImportParameters(publicKey.AsRsaParameters());
            return rsa.VerifyData(signature, CryptoConfig.MapNameToOID("SHA512"), signedData);
        }

        /// <summary>
        /// Composes a signature as a SHA512 hash to be signed based on the request and authentication information.
        /// </summary>
        /// <param name="request">
        /// The request which has the information (method, url and content) for the signature.
        /// </param>
        /// <param name="authInfo">
        /// The <see cref="AuthenticationInfo"/> which holds the application uuid and the time of the signature.
        /// </param>
        /// <returns>A Task object which will result the byte value of signature when it completes.</returns>
        public async Task<byte[]> GetSignature(HttpRequestMessage request, AuthenticationInfo authInfo)
        {
            var requestContents = await request.GetRequestContentAsBytesAsync().ConfigureAwait(false);
            return GetSignatureInternal(request, authInfo, requestContents);
        }

        /// <summary>
        /// Composes a signature as a SHA512 hash to be signed based on the request and authentication information.
        /// </summary>
        /// <param name="request">
        /// The request which has the information (method, url and content) for the signature.
        /// </param>
        /// <param name="authInfo">
        /// The <see cref="AuthenticationInfo"/> which holds the application uuid and the time of the signature.
        /// </param>
        /// <param name="requestContents">
        /// The request body as a byte array.
        /// </param>
        /// <returns>A Task object which will result the byte value of signature when it completes.</returns>
        internal byte[] GetSignatureInternal(HttpRequestMessage request, AuthenticationInfo authInfo, byte[] requestContents)
        {
            var encodedHttpVerb = request.Method.Method.ToBytes();
            var encodedResourceUriPath = request.RequestUri.AbsolutePath.NormalizeUriPath().ToBytes();
            var encodedAppUUid = authInfo.ApplicationUuid.ToHyphenString().ToBytes();

            var requestBody = requestContents ?? Array.Empty<byte>();

            var requestBodyDigest = requestBody.AsSHA512Hash();

            var encodedCurrentSecondsSinceEpoch = authInfo.SignedTime.ToUnixTimeSeconds().ToString().ToBytes();
            var queryString = request.RequestUri.Query;
            var encodedQueryParams = !string.IsNullOrEmpty(queryString)
                ? queryString.Substring(1).BuildEncodedQueryParams().ToBytes()
                : new byte[] { };

            return new byte[][]
            {
                encodedHttpVerb, Constants.NewLine,
                encodedResourceUriPath, Constants.NewLine,
                requestBodyDigest, Constants.NewLine,
                encodedAppUUid, Constants.NewLine,
                encodedCurrentSecondsSinceEpoch, Constants.NewLine,
                encodedQueryParams
            }.Concat();
        }

        /// <summary>
        /// Adds authentication information to a <see cref="HttpRequestMessage"/>. 
        /// </summary>
        /// <param name="request">The request to add the information to.</param>
        /// <param name="authInfo">
        /// The authentication information with a private key to calculate the payload with.
        /// </param>
        /// <param name="requestContents">
        /// The request body as a byte array.
        /// </param>
        /// <returns>
        /// A Task object which will result the request with the authentication information added when it completes.
        /// </returns>
        internal HttpRequestMessage AddAuthenticationInfo(
            HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo, byte[] requestContents)
        {
            var authHeader =
                $"{MAuthVersion.MWSV2} {authInfo.ApplicationUuid.ToHyphenString()}:" +
                $"{CalculatePayload(request, authInfo, requestContents)};";

            request.Headers.Add(Constants.MAuthHeaderKeyV2, authHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKeyV2, authInfo.SignedTime.ToUnixTimeSeconds().ToString());

            return request;
        }

        /// <summary>
        /// Calculates the payload information based on the request and the authentication information.
        /// </summary>
        /// <param name="request">
        /// The request which has the information (method, url and content) for the calculation.
        /// </param>
        /// <param name="authInfo">
        /// The <see cref="PrivateKeyAuthenticationInfo"/> which holds the application uuid, the time of the
        /// signature and the private key.
        /// </param>
        /// <param name="requestContents">
        /// The request body as a byte array.
        /// </param>
        /// <returns>A task object which will result the payload as a Base64 encoded string when completed.</returns>
        internal string CalculatePayload(
            HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo, byte[] requestContents)
        {
            
            var unsignedData = GetSignatureInternal(request, authInfo, requestContents);
            var signer = new RSACryptoServiceProvider();
            signer.PersistKeyInCsp = false;
            signer.ImportParameters(authInfo.PrivateKey.AsRsaParameters());

            return Convert.ToBase64String(signer.SignData(unsignedData, CryptoConfig.MapNameToOID("SHA512")));
        }

        /// <summary>
        /// Gets the MAuthHeader and MAuthTimeHeader keys.
        /// </summary>
        /// <returns>MAuthHeaderKey and MAuthTimeHeaderKey.</returns>
        public (string mAuthHeaderKey, string mAuthTimeHeaderKey) GetHeaderKeys()
        {
            return (Constants.MAuthHeaderKeyV2, Constants.MAuthTimeHeaderKeyV2);
        }

#if NET5_0
        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="options">The options that contains the required information for the signing.</param>
        /// <returns>
        /// A Task object which will result the request signed with the authentication information when it completes.
        /// </returns>
        public HttpRequestMessage SignSync(
            HttpRequestMessage request, MAuthSigningOptions options)
        {
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey.Dereference().NormalizeLines()
            };
            var requestContents = request.GetRequestContentAsBytes();
            return AddAuthenticationInfo(request, authInfo, requestContents);
        }
        #endif
    }
}
