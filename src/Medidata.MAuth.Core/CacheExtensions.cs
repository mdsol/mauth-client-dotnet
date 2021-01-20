using System;
using Microsoft.Extensions.Caching.Memory;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Caching-related extension methods.
    /// </summary>
    public static class CacheExtensions
    {
        /// <summary>
        /// Get or create an item in the cache.  If the specified key does not exist, the factory method will be executed to
        /// create a new item, and that item will be inserted into the cache with that key.  Locking is based on the cache
        /// key, to prevent multiple concurrent factory methods from executing for a single key, but allow multiple concurrent
        /// factory methods to execute for different keys.
        /// </summary>
        /// <param name="cache">The memory cache.</param>
        /// <param name="key">The cache key.</param>
        /// <param name="factory">The factory method to create a new item if the key does not exist in the cache.</param>
        /// <typeparam name="TItem">The cached item type.</typeparam>
        /// <returns>The item that was retrieved from the cache or created.</returns>
        public static TItem GetOrCreateWithLock<TItem>(
            this IMemoryCache cache,
            object key,
            Func<ICacheEntry, TItem> factory)
        {
            if (cache.TryGetValue(key, out TItem item))
            {
                return item;
            }

            var lockStr = string.Intern("mutex_" + key.GetHashCode());

            lock (lockStr)
            {
                if (cache.TryGetValue(key, out item))
                {
                    return item;
                }

                ICacheEntry entry = cache.CreateEntry(key);
                item = factory(entry);
                entry.SetValue(item);
                entry.Dispose();
                return item;
            }
        }
    }
}
