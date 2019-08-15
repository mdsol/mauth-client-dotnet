using System;

namespace Medidata.MAuth.Core.Exceptions
{
    /// <summary>
    /// The exception that is thrown when version no longer allowed is passed.
    /// </summary>
    public class InvalidVersionException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidVersionException"/> class with the specified message.
        /// </summary>
        /// <param name="message">A message that describes the invalid version failure.</param>
        public InvalidVersionException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidVersionException"/> class with the specified message
        /// and inner exception.
        /// </summary>
        /// <param name="message">A message that describes the invalid version failure.</param>
        /// <param name="innerException">An exception that is the cause of the current exception.</param>
        public InvalidVersionException(string message, Exception innerException) : base(message, innerException) { }
    }
}
