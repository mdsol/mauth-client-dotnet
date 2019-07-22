using System;
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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Utilities.Encoders;

namespace Medidata.MAuth.Core
{
    internal static class MAuthCoreExtensions
    {
        /// <summary>
        /// Deserializes an <see cref="ApplicationInfo"/> object from a content of a Http message. 
        /// </summary>
        /// <param name="content">The content to deserialize the information from.</param>
        /// <returns>A Task object which will result the application information when it completes.</returns>
        public static async Task<ApplicationInfo> FromResponse(this HttpContent content)
        {
            var jsonObject = JObject.Parse(await content.ReadAsStringAsync().ConfigureAwait(false));

            return jsonObject.GetValue("security_token").ToObject<ApplicationInfo>();
        }

        /// <summary>
        /// Converts a <see cref="DateTimeOffset"/> value to a Unix equivalent time value. 
        /// </summary>
        /// <param name="value">The date and time to be converted.</param>
        /// <returns>The total seconds elapsed from the Unix epoch (1970-01-01 00:00:00).</returns>
        public static long ToUnixTimeSeconds(this DateTimeOffset value) =>
            (long)(value - Constants.UnixEpoch).TotalSeconds;

        /// <summary>
        /// Converts a <see cref="long"/> value that is a Unix time in seconds to a UTC <see cref="DateTimeOffset"/>. 
        /// </summary>
        /// <param name="value">The Unix time seconds to be converted.</param>
        /// <returns>The <see cref="DateTimeOffset"/> equivalent of the Unix time.</returns>
        public static DateTimeOffset FromUnixTimeSeconds(this long value) =>
            Constants.UnixEpoch.AddSeconds(value);

        /// <summary>
        /// Returns the hyphenated representation of a <see cref="Guid"/> as a <see cref="string"/>. 
        /// </summary>
        /// <param name="uuid">The <see cref="Guid"/> to convert to the hyphenated string.</param>
        /// <returns>The uuid in a format with hyphens.</returns>
        public static string ToHyphenString(this Guid uuid) =>
            uuid.ToString("D").ToLower();

        /// <summary>
        /// Provides the first value with a given key from a collection of HTTP headers or a default value if the
        /// key is not found.
        /// </summary>
        /// <typeparam name="TValue">The type of the value to search for.</typeparam>
        /// <param name="headers">The collection of the HTTP headers to search in.</param>
        /// <param name="key">The key to search in the headers collection.</param>
        /// <returns>The value if found; otherwise a default value for the given type.</returns>
        public static TValue GetFirstValueOrDefault<TValue>(this HttpHeaders headers, string key) =>
            headers.TryGetValues(key, out IEnumerable<string> values) ?
                (TValue)Convert.ChangeType(values.First(), typeof(TValue)) :
                default(TValue);

        /// <summary>
        /// Provides an SHA512 hash value of a string.
        /// </summary>
        /// <param name="value">The value for calculating the hash.</param>
        /// <returns>The SHA512 hash of the input value as a hex-encoded byte array.</returns>
        public static byte[] AsSHA512Hash(this string value) =>
            AsSHA512Hash(Encoding.UTF8.GetBytes(value));

        public static byte[] AsSHA512Hash(this byte[] value) =>
            Hex.Encode(SHA512.Create().ComputeHash(value));

        /// <summary>
        /// Provides a string PEM (ASN.1) format key as an <see cref="ICipherParameters"/> object.
        /// </summary>
        /// <param name="key">The PEM key in ASN.1 format.</param>
        /// <returns>The cipher parameters extracted from the key.</returns>
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

        /// <summary>
        /// Sets the stream position to 0 if the stream is seekable; otherwise it will return the stream with its
        /// current position.
        /// </summary>
        /// <param name="stream">The stream to rewind.</param>
        /// <returns>
        /// The passed stream with its position set to 0, or the position unchanged if the stream is not seekable.
        /// </returns>
        public static Stream Rewind(this Stream stream)
        {
            if (stream.CanSeek)
                stream.Seek(0, SeekOrigin.Begin);

            return stream;
        }

        public static string Dereference(this string keyPathOrKey) =>
            keyPathOrKey.IsValidPath() ? File.ReadAllText(keyPathOrKey) : keyPathOrKey;

        public static string NormalizeLines(this string key) =>
            key.RemoveLineBreaks().InsertLineBreakAfterBegin().InsertLineBreakBeforeEnd();

        public static bool IsValidPath(this string value) =>
            Uri.TryCreate(value, UriKind.Absolute, out var pathUri) && pathUri.IsLoopback;

        private static string RemoveLineBreaks(this string key) =>
            key.Replace("\r", string.Empty).Replace("\n", string.Empty);

        private static string InsertLineBreakAfterBegin(this string key) =>
            Regex.Replace(key, Constants.KeyNormalizeLinesStartRegexPattern, "${begin}\n");

        private static string InsertLineBreakBeforeEnd(this string key) =>
            Regex.Replace(key, Constants.KeyNormalizeLinesEndRegexPattern, "\n${end}");


        public static byte[] ToBytes(this string value) => Encoding.UTF8.GetBytes(value);

        public static byte[] Concat(this byte[][] values)
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
    }
}
