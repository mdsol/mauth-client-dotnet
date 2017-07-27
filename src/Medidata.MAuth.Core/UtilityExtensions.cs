using System;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains utility extension methods for MAuth.
    /// </summary>
    public static class UtilityExtensions
    {
        /// <summary>
        /// Parses an MAuth authentication HTTP header value for the application uuid and the MAuth signature payload.
        /// If the parsing is not successful, an <see cref="ArgumentException"/> is thrown.
        /// </summary>
        /// <param name="headerValue">
        /// The value of the X-MWS-Authentication HTTP header containing the application uuid and the MAuth signature
        /// payload.
        /// </param>
        /// <returns>The application uuid and the payload encoded with Base64 encoding.</returns>
        public static (Guid Uuid, string Base64Payload) ParseAuthenticationHeader(this string headerValue) =>
            headerValue.TryParseAuthenticationHeader(out var result) ?
                result :
                throw new ArgumentException("Invalid MAuth authentication header value.", nameof(headerValue));

        /// <summary>
        /// Parses an MAuth authentication HTTP header value for the application uuid and the MAuth signature payload.
        /// A return value indicates whether the parsing succeeded.
        /// </summary>
        /// <param name="headerValue">
        /// The value of the X-MWS-Authentication HTTP header containing the application uuid and the MAuth signature
        /// payload.
        /// </param>
        /// <param name="result">
        /// When this method returns, contains the application uuid and the Base64 encoded MAuth signature
        /// payload contained in <paramref name="headerValue"/> if the parsing succeeded, or the default value of a
        /// (<see cref="Guid"/>, <see cref="string"/>) tuple if the parsing failed. The parsing fails if the
        /// <paramref name="headerValue"/> is <see langword="null"/> or <see cref="string.Empty"/>, or not of the
        /// correct format. This parameter is passed uninitialized; any value originally supplied in
        /// <paramref name="result"/> will be overwritten.</param>
        /// <returns>
        /// <see langword="true"/> if <paramref name="headerValue"/> was parsed successfully; otherwise,
        /// <see langword="false"/>.
        /// </returns>
        public static bool TryParseAuthenticationHeader(this string headerValue,
            out (Guid Uuid, string Base64Payload) result)
        {
            var match = Constants.AuthenticationHeaderRegex.Match(headerValue);

            result = default((Guid, string));

            if (!match.Success)
                return false;

            result.Uuid = new Guid(match.Groups["uuid"].Value);
            result.Base64Payload = match.Groups["payload"].Value;

            return true;
        }
    }
}
