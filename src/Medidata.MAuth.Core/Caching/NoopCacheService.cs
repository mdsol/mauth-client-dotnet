using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core.Caching
{
    /// <summary>
    /// Noop Cache Service
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class NoopCacheService : ICacheService
    {
        /// <summary>
        /// Gets or create cache item with locking.
        /// </summary>
        /// <typeparam name="TItem">The cached item type.</typeparam>
        /// <param name="key">Cache Key</param>
        /// <param name="factory">Factory method to create cached item</param>
        /// <returns>Cached Item</returns>
        public async Task<TItem> GetOrCreateWithLock<TItem>(
            string key,
            Func<Task<CacheResult<TItem>>> factory)
        {
            var data = await factory().ConfigureAwait(false);
            return data.Result;
        }

        /// <summary>
        /// Remove key from cache if exists.
        /// </summary>
        /// <param name="key"></param>
        public void Remove(string key)
        {
        }
    }
}
