using System;

namespace Medidata.MAuth.Core
{
    internal class DateTimeOffsetWrapper : IDateTimeOffsetWrapper
    {
        /// <summary>
        /// A facade around DatetimeOffset.UtcNow
        /// </summary>
        /// <returns>
        /// The value of DateTimeOffset.UtcNow
        /// </returns>
        public DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow;
    }
}
