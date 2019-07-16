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

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// 
    /// </summary>
    internal static class MAuthCoreExtensionsV2
    {
        private const string MwsV2Token = "MWSV2";

        //Response Signing

        // 1) Sign the response body separately from the rest of the response so that it does not have to be read into the memory all at once.
        // 2) Force UTF-8 encoding of all text (e.g. status code, app_uuid etc.) 

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
        public static async Task<string> CalculatePayloadV2(
            this HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var unsignedData = await request.GetSignatureV2(authInfo).ConfigureAwait(false);
            var signer = new RSACryptoServiceProvider();

            return Convert.ToBase64String(signer.SignHash(unsignedData, authInfo.PrivateKey));
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
        public static bool VerifyV2(this byte[] signedData, byte[] signature, string publicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            return rsa.VerifyHash(signedData, publicKey, signature);
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
        public static async Task<byte[]> GetSignatureV2(this HttpRequestMessage request, AuthenticationInfo authInfo)
        {
            var encodedHttpVerb = request.Method.Method.ToBytes();
            //var encodedResourceUriPath = Uri.EscapeUriString(request.RequestUri.AbsolutePath);
            var encodedResourceUriPath = request.RequestUri.AbsolutePath.ToBytes();
            var encodedAppUUid = authInfo.ApplicationUuid.ToHyphenString().ToBytes();

            var requestBody = request.Content != null ?
                await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false) : new byte[] { };
            // var requestBodyDigest = SHA512 hash of request body
            // UTF-8 encode the resulting hash
            var requestBodyDigest = requestBody.AsSha512HashV2();
            //var requestBodyDigest = Encoding.UTF8.GetString(SHA512.Create().ComputeHash(requestBody));

            var encodedCurrentSecondsSinceEpoch = authInfo.SignedTime.ToUnixTimeSeconds().ToString().ToBytes();

            var encodedQueryParams = request.GetQueryStringParams().SortByKeyAscending().BuildEncodedQueryParams().ToBytes();

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
        /// Extracts the authentication information from a <see cref="HttpRequestMessage"/>.
        /// </summary>
        /// <param name="request">The request that has the authentication information.</param>
        /// <returns>The authentication information with the payload from the request.</returns>
        public static PayloadAuthenticationInfo GetAuthenticationInfoV2(this HttpRequestMessage request)
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
        public static async Task<HttpRequestMessage> AddAuthenticationInfoV2(
            this HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var authHeader =
                $"{MwsV2Token} {authInfo.ApplicationUuid.ToHyphenString()}:" +
                $"{await request.CalculatePayloadV2(authInfo).ConfigureAwait(false)};";

            request.Headers.Add(Constants.MAuthHeaderKeyV2, authHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKeyV2, authInfo.SignedTime.ToUnixTimeSeconds().ToString());

            return request;
        }

        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="options">The options that contains the required information for the signing.</param>
        /// <returns>
        /// A Task object which will result the request signed with the authentication information when it completes.
        /// </returns>
        public static async Task<HttpRequestMessage> SignV2(
            this HttpRequestMessage request, MAuthSigningOptions options)
        {
            return await request.AddAuthenticationInfoV2(new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = options.ApplicationUuid,
                SignedTime = options.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = options.PrivateKey.Dereference().NormalizeLines()
            });
        }


        /// <summary>
        /// Deserializes an <see cref="ApplicationInfo"/> object from a content of a Http message. 
        /// </summary>
        /// <param name="content">The content to deserialize the information from.</param>
        /// <returns>A Task object which will result the application information when it completes.</returns>
        public static async Task<ApplicationInfo> FromResponseV2(this HttpContent content)
        {
            var jsonObject = JObject.Parse(await content.ReadAsStringAsync().ConfigureAwait(false));

            return jsonObject.GetValue("security_token").ToObject<ApplicationInfo>();
        }

        /// <summary>
        /// Provides an SHA512 hash value of bytes.
        /// </summary>
        /// <param name="value">The byte value for calculating the hash.</param>
        /// <returns>The UTF8 encoded bytes of SHA512 hash of the input value as a hex-encoded byte array.</returns>
        private static byte[] AsSha512HashV2(this byte[] value) =>
            Encoding.UTF8.GetBytes(SHA512.Create().ComputeHash(value).ToString());

        private static byte[] ToBytes(this string value) => Encoding.UTF8.GetBytes(value);

        private static byte[] Concat(this byte[][] values)
        {
            var result = new byte[values.Sum(x => x.Length)];
            var offset = 0;
            foreach (var value in values)
            {
                Buffer.BlockCopy(value, 0, result, offset, value.Length);
                offset += value.Length;
            }

            return result;
        }

        private static IDictionary<string, string> GetQueryStringParams(this HttpRequestMessage request)
        {
            var query = request.RequestUri.Query;
            var dictionary = query.Replace("?", "").Split('&').ToDictionary(x => x.Split('=')[0], x => x.Split('=')[1]);
            return dictionary;
        }

        private static IDictionary<string, string> SortByKeyAscending(this IDictionary<string, string> queryStringParams)
        {
            var sortDictionary = new Dictionary<string, string>();
            var list = queryStringParams.Keys.ToList();
            list.Sort();
            foreach (var key in list)
            {
                sortDictionary.Add(key, queryStringParams[key]);
            }
            return sortDictionary;
        }

        private static string BuildEncodedQueryParams(this IDictionary<string, string> queryParams)
        {
            var encodedQueryParam = string.Empty;
            foreach (var key in queryParams.Keys)
            {
                encodedQueryParam = (encodedQueryParam != string.Empty) ?
                    $"{encodedQueryParam}&" : encodedQueryParam;

                var encodedKey = Encoding.UTF8.GetBytes(key); // Is this UTF8 encoding or URI encoding

                var encodedValue = (queryParams[key] != string.Empty)
                    ? Encoding.UTF8.GetBytes(queryParams[key])    // same here UTF8 encoding or uri encoding
                    : new byte[] { };
                encodedQueryParam = $"{encodedQueryParam}{encodedKey}={encodedValue}";
            }
            return encodedQueryParam;
        }
    }
}
