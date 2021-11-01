using System;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core.Caching
{
    /// <summary>
    /// Caching abstraction
    /// </summary>
    public interface ICacheService
    {
        /// <summary>
        /// Gets or create cache item with locking.
        /// </summary>
        /// <typeparam name="TItem">The cached item type.</typeparam>
        /// <param name="key">Cache Key</param>
        /// <param name="factory">Factory method to create cached item</param>
        /// <returns>The item that was retrieved from the cache or created.</returns>
        Task<TItem> GetOrCreateWithLock<TItem>(
            string key,
            Func<Task<CacheResult<TItem>>> factory);

        /// <summary>
        /// Remove key from cache if exists.
        /// </summary>
        /// <param name="key"></param>
        void Remove(string key);
    }
}
