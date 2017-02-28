using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// The exception that is thrown when a number of request attempts to the MAuth server fails.
    /// </summary>
    public class RetriedRequestException: Exception
    {
        /// <summary>
        /// Determines the responses for each request attempts made.
        /// </summary>
        public ICollection<HttpResponseMessage> Responses { get; } = new List<HttpResponseMessage>();

        /// <summary>
        /// Determines the request message of the first request attempt to the MAuth server.
        /// </summary>
        public HttpRequestMessage Request { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RetriedRequestException"/> class with the specified message.
        /// </summary>
        /// <param name="message">A message that describes the request failure.</param>
        public RetriedRequestException(string message): base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="RetriedRequestException"/> class with the specified message
        /// and inner exception.
        /// </summary>
        /// <param name="message">A message that describes the request failure.</param>
        /// <param name="innerException">An exception that is the cause of the current exception.</param>
        public RetriedRequestException(string message, Exception innerException): base(message, innerException) { }
    }
}
