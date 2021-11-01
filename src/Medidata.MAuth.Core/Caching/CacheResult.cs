using System;

namespace Medidata.MAuth.Core.Caching
{
    /// <summary>
    /// Dto to store cache fields
    /// </summary>
    /// <typeparam name="TItem">Cache result type.</typeparam>
    public class CacheResult<TItem>
    {
        /// <summary>
        /// Item to store in cache.
        /// </summary>
        public TItem Result { get; set; }

        /// <summary>
        /// Flag to determine if the result should be cache.
        /// </summary>
        public bool ShouldCache { get; set; }

        /// <summary>
        /// Cache duration.
        /// </summary>
        public TimeSpan AbsoluteCacheDuration { get; set; }
    }
}