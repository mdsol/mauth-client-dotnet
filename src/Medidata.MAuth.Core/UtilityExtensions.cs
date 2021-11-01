using System;
using System.Net.Http;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Caching;
using Medidata.MAuth.Core.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Contains utility extension methods for MAuth.
    /// </summary>
    public static class UtilityExtensions
    {
        private static readonly ICacheService _cache 
            = new MemoryCacheService(new MemoryCache(new MemoryCacheOptions()));

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
            var match = headerValue.Contains("MWSV2") ? Constants.AuthenticationHeaderRegexV2.Match(headerValue) :
                Constants.AuthenticationHeaderRegex.Match(headerValue);

            result = default((Guid, string));

            if (!match.Success)
                return false;

            result.Uuid = new Guid(match.Groups["uuid"].Value);
            result.Base64Payload = match.Groups["payload"].Value;

            return true;
        }

        /// <summary>
        /// Authenticates a <see cref="HttpRequestMessage"/> with the provided options.
        /// </summary>
        /// <param name="request">The request message to authenticate.</param>
        /// <param name="options">The MAuth options to use for the authentication.</param>
        /// <param name="logger">The logger interface used for logging.</param>
        /// <returns>The task for the operation that is when completes will result in <see langword="true"/> if
        /// the authentication is successful; otherwise <see langword="false"/>.</returns>
        public static Task<bool> Authenticate(this HttpRequestMessage request, MAuthOptionsBase options, ILogger logger) =>
                new MAuthAuthenticator(options, logger, _cache).AuthenticateRequest(request);

        /// <summary>
        /// Determines the MAuth version enumerator reading authHeader.
        /// </summary>
        /// <param name="authHeader"></param>
        /// <returns>Enumeration value of MAuthVersion.</returns>
        public static MAuthVersion GetVersionFromAuthenticationHeader(this string authHeader)
        {
            return authHeader.StartsWith(MAuthVersion.MWSV2.ToString())
                ? MAuthVersion.MWSV2 : MAuthVersion.MWS;
        }

        /// <summary>
        /// Determines the correct MAuthHeader value with default check for V2.
        /// </summary>
        /// <param name="request"></param>
        /// <returns>The MAuthHeader value.</returns>
        public static string GetAuthHeaderValue(this HttpRequestMessage request)
        {
            //By default first check for V2
            var authHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2)
                             ?? request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);
            return authHeader ??
                   throw new ArgumentNullException(nameof(authHeader), "The MAuth header is missing from the request.");
        }
    }
}
