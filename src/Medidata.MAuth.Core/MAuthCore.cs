﻿using Org.BouncyCastle.Crypto.Encodings;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    internal class MAuthCore: IMAuthCore
    {
        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="options">The options that contains the required information for the signing.</param>
        /// <returns>
        /// A Task object which will result the request signed with the authentication information when it completes.
        /// </returns>
        public async Task<HttpRequestMessage> Sign(HttpRequestMessage request, MAuthSigningOptions options)
        {
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey
            };

            var contents = await request.GetRequestContentAsBytesAsync().ConfigureAwait(false);
            return AddAuthenticationInfo(request, authInfo, contents);
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
            Pkcs1Encoding.StrictLengthEnabled = false;
            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(false, publicKey.AsCipherParameters());

            return cipher.DoFinal(signedData).SequenceEqual(signature);
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
            var contents = await request.GetRequestContentAsBytesAsync().ConfigureAwait(false);
            return GenerateSignature(request, authInfo, contents);
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
        /// <returns>A Task object which will result the SHA512 hash of the signature when it completes.</returns>
        internal byte[] GenerateSignature(HttpRequestMessage request, AuthenticationInfo authInfo, byte[] requestContents)
        {
            return new byte[][]
                 {
                    request.Method.Method.ToBytes(), Constants.NewLine,
                    request.RequestUri.AbsolutePath.ToBytes(), Constants.NewLine,
                    requestContents ?? Array.Empty<byte>(),
                    Constants.NewLine,
                    authInfo.ApplicationUuid.ToHyphenString().ToBytes(), Constants.NewLine,
                    authInfo.SignedTime.ToUnixTimeSeconds().ToString().ToBytes()
                 }
                 .Concat()
                 .AsSHA512Hash();
        }

        /// <summary>
        /// Adds authentication information to a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request to add the information to.</param>
        /// <param name="authInfo">
        /// The authentication information with a private key to calculate the payload with.
        /// </param>
        /// <param name="requestContent">
        /// The request body as a byte array.
        /// </param>
        /// <returns>
        /// A Task object which will result the request with the authentication information added when it completes.
        /// </returns>
        internal HttpRequestMessage AddAuthenticationInfo(HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo, byte[] requestContent)
        {
            var authHeader =
                $"{MAuthVersion.MWS} {authInfo.ApplicationUuid.ToHyphenString()}:" +
                $"{CalculatePayload(request, authInfo, requestContent)}";

            request.Headers.Add(Constants.MAuthHeaderKey, authHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKey, authInfo.SignedTime.ToUnixTimeSeconds().ToString());

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
        /// <param name="requestContent">
        /// The request body as a byte array.
        /// </param>
        /// <returns>A task object which will result the payload as a Base64 encoded string when completed.</returns>
        internal string CalculatePayload(HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo, byte[] requestContent)
        {
            var unsignedData =  GenerateSignature(request, authInfo, requestContent);
            var signer = new Pkcs1Encoding(new RsaEngine());
            signer.Init(true, authInfo.PrivateKey.AsCipherParameters());

            return Convert.ToBase64String(signer.ProcessBlock(unsignedData, 0, unsignedData.Length));
        }

        /// <summary>
        /// Gets the MAuthHeader and MAuthTimeHeader keys
        /// </summary>
        /// <returns>MAuthHeaderKey and MAuthTimeHeaderKey.</returns>
        public (string mAuthHeaderKey, string mAuthTimeHeaderKey) GetHeaderKeys()
        {
            return (Constants.MAuthHeaderKey, Constants.MAuthTimeHeaderKey);
        }

#if NET5_0
        public HttpRequestMessage SignSync(HttpRequestMessage request, MAuthSigningOptions options)
        {
            var authInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey
            };

            var contents = request.GetRequestContentAsBytes();
            return AddAuthenticationInfo(request, authInfo, contents);
        }
#endif
    }
}
