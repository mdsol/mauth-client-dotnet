using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// 
    /// </summary>
    internal class MAuthCoreV2 : IMAuthCore
    {
        private const string MwsV2Token = "MWSV2";

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
            return await AddAuthenticationInfo(request, new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey.Dereference().NormalizeLines()
            });
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
            return rsa.VerifyHash(signature, CryptoConfig.MapNameToOID("SHA512"), signedData);
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
        /// <returns>A Task object which will result the SHA512 hash of the signature when it completes.</returns>
        public async Task<byte[]> GetSignature(HttpRequestMessage request, AuthenticationInfo authInfo)
        {
            var encodedHttpVerb = request.Method.Method.ToBytes();
            var encodedResourceUriPath = request.RequestUri.AbsolutePath.ToBytes();
            var encodedAppUUid = authInfo.ApplicationUuid.ToHyphenString().ToBytes();

            var requestBody = request.Content != null ?
                await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false) : new byte[] { };
            // var requestBodyDigest = SHA512 hash of request body
            var requestBodyDigest = requestBody.AsSha512HashV2();

            var encodedCurrentSecondsSinceEpoch = authInfo.SignedTime.ToUnixTimeSeconds().ToString().ToBytes();

            var encodedQueryParams =  (!string.IsNullOrEmpty(request.RequestUri.Query))
                ? request.RequestUri.Query.GetQueryStringParams().SortByKeyAscending().BuildEncodedQueryParams().ToBytes()
                : new byte[] { };

            return new byte[][]
            {
                encodedHttpVerb, Constants.NewLine,
                encodedResourceUriPath, Constants.NewLine,
                requestBodyDigest, Constants.NewLine,
                encodedAppUUid, Constants.NewLine,
                encodedCurrentSecondsSinceEpoch, Constants.NewLine,
                encodedQueryParams
            }.Concat().AsSha512HashV2();
        }

        /// <summary>
        /// Adds authentication information to a <see cref="HttpRequestMessage"/>. 
        /// </summary>
        /// <param name="request">The request to add the information to.</param>
        /// <param name="authInfo">
        /// The authentication information with a private key to calculate the payload with.
        /// </param>
        /// <returns>
        /// A Task object which will result the request with the authentication information added when it completes.
        /// </returns>
        internal async Task<HttpRequestMessage> AddAuthenticationInfo(
            HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var authHeader =
                $"{MwsV2Token} {authInfo.ApplicationUuid.ToHyphenString()}:" +
                $"{await CalculatePayload(request, authInfo).ConfigureAwait(false)};";

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
        /// <returns>A task object which will result the payload as a Base64 encoded string when completed.</returns>
        internal async Task<string> CalculatePayload(
            HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var unsignedData = await GetSignature(request, authInfo).ConfigureAwait(false);
            var signer = new RSACryptoServiceProvider();
            signer.PersistKeyInCsp = false;
            signer.ImportParameters(authInfo.PrivateKey.AsRsaParameters());

            return Convert.ToBase64String(signer.SignHash(unsignedData, CryptoConfig.MapNameToOID("SHA512")));
        }

        /// <summary>
        /// Extracts the authentication information from a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request that has the authentication information.</param>
        /// <returns>The authentication information with the payload from the request.</returns>
        public PayloadAuthenticationInfo GetAuthenticationInfo(HttpRequestMessage request)
        {
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2);

            if (authHeader == null)
                throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKeyV2);

            if (signedTime == default(long))
                throw new ArgumentException("Invalid MAuth signed time header value.", nameof(signedTime));

            var (uuid, payload) = authHeader.ParseAuthenticationHeader();

            return new PayloadAuthenticationInfo()
            {
                ApplicationUuid = uuid,
                Payload = Convert.FromBase64String(payload),
                SignedTime = signedTime.FromUnixTimeSeconds()
            };
        }
    }
}
