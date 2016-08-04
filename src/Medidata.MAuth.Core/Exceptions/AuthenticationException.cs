using System;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// The exception that is thrown when authentication fails for an HTTP request.
    /// </summary>
    public class AuthenticationException: Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationException"/> class with the specified message
        /// and inner exception.
        /// </summary>
        /// <param name="message">A message that describes the authentication failure.</param>
        /// <param name="innerException">An exception that is the cause of the current exception.</param>
        public AuthenticationException(string message, Exception innerException): base(message, innerException) { }
    }
}
