using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Medidata.MAuth.Core
{
    internal static class MAuthCoreExtensions
    {
        public static async Task<string> CalculatePayload(
            this HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var unsignedData = await request.GetSignature(authInfo);
            var signer = new Pkcs1Encoding(new RsaEngine());
            signer.Init(true, authInfo.PrivateKey.AsCipherParameters());

            return Convert.ToBase64String(signer.ProcessBlock(unsignedData, 0, unsignedData.Length));
        }

        public static Task<bool> Verify(this byte[] signedData, byte[] signature, string publicKey)
        {
            Pkcs1Encoding.StrictLengthEnabled = false;
            var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            cipher.Init(false, publicKey.AsCipherParameters());

            return Task.Run(() => cipher.DoFinal(signedData).SequenceEqual(signature));
        }

        public static async Task<byte[]> GetSignature(this HttpRequestMessage request, AuthenticationInfo authInfo)
        {
            return 
                ($"{request.Method.Method}\n" +
                $"{request.RequestUri.AbsolutePath}\n" +
                $"{(request.Content != null ? await request.Content.ReadAsStringAsync() : string.Empty)}\n" +
                $"{authInfo.ApplicationUuid.ToHyphenString()}\n" +
                $"{authInfo.SignedTime.ToUnixTimeSeconds()}")
                .AsSHA512Hash();
        }

        public static PayloadAuthenticationInfo GetAuthenticationInfo(this HttpRequestMessage request)
        {
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);

            if (authHeader == null)
                throw new ArgumentNullException("The MAuth header is missing from the request.", nameof(authHeader));

            var signedTime = request.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey);

            if (signedTime == default(long))
                throw new ArgumentException("Invalid MAuth signed time header value.", nameof(signedTime));

            var match = Constants.AuthenticationHeaderRegex.Match(authHeader);

            if (!match.Success)
                throw new ArgumentException("Invalid MAuth authentication header value.", nameof(authHeader));

            return new PayloadAuthenticationInfo()
            {
                ApplicationUuid = new Guid(match.Groups["uuid"].Value),
                Payload = Convert.FromBase64String(match.Groups["payload"].Value),
                SignedTime = signedTime.FromUnixTimeSeconds()
            };
        }

        public async static Task<HttpRequestMessage> AddAuthenticationInfo(
            this HttpRequestMessage request, PrivateKeyAuthenticationInfo authInfo)
        {
            var authHeader =
                $"MWS {authInfo.ApplicationUuid.ToHyphenString()}:" +
                $"{await request.CalculatePayload(authInfo)}";

            request.Headers.Add(Constants.MAuthHeaderKey, authHeader);
            request.Headers.Add(Constants.MAuthTimeHeaderKey, authInfo.SignedTime.ToUnixTimeSeconds().ToString());

            return request;
        }

        public async static Task<ApplicationInfo> FromResponse(this HttpContent content)
        {
            var jsonObject = JObject.Parse(await content.ReadAsStringAsync());

            return jsonObject.GetValue("security_token").ToObject<ApplicationInfo>();
        }

        /// <summary>
        /// Converts a <see cref="DateTimeOffset"/> value to a Unix equivalent time value. 
        /// </summary>
        /// <param name="value">The date and time to be converted.</param>
        /// <returns>The total seconds elapsed from the Unix epoch (1970-01-01 00:00:00).</returns>
        public static long ToUnixTimeSeconds(this DateTimeOffset value)
        {
            return (long)(value - Constants.UnixEpoch).TotalSeconds;
        }

        public static DateTimeOffset FromUnixTimeSeconds(this long value)
        {
            return Constants.UnixEpoch.AddSeconds(value);
        }

        public static string ToHyphenString(this Guid uuid)
        {
            return uuid.ToString("D").ToLower();
        }

        public static TValue GetFirstValueOrDefault<TValue>(this HttpHeaders headers, string key)
        {
            IEnumerable<string> values;

            return headers.TryGetValues(key, out values) ?
                (TValue)Convert.ChangeType(values.First(), typeof(TValue)) :
                default(TValue);
        }

        public static byte[] AsSHA512Hash(this string value)
        {
            return Hex.Encode(SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(value)));
        }

        public static ICipherParameters AsCipherParameters(this string key)
        {
            using (var reader = new StringReader(key))
            {
                var keyObject = new PemReader(reader).ReadObject();

                if (keyObject is AsymmetricCipherKeyPair)
                    return ((AsymmetricCipherKeyPair)keyObject).Private;

                return keyObject as RsaKeyParameters;
            }
        }
    }
}
