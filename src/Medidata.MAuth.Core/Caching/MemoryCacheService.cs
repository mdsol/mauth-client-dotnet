using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace Medidata.MAuth.Core.Caching
{
    /// <summary>
    /// In-Memory Cache service
    /// </summary>
    public class MemoryCacheService : ICacheService
    {
        private readonly IMemoryCache _cache;

        /// <summary>
        /// In Memory Cache Service
        /// </summary>
        /// <param name="cache"></param>
        public MemoryCacheService(IMemoryCache cache)
        {
            _cache = cache;
        }

        /// <summary>
        /// Checks if key is in the cache
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns>True when key found in cache.</returns>
        public bool TryGetValue<T>(string key, out T value)
            => _cache.TryGetValue(key, out value);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        public void Remove(string key) => _cache.Remove(key);

        /// <summary>
        /// Add an item to the cache.
        /// </summary>
        /// <param name="key">Cache Key</param>
        /// <param name="value">Item to cache</param>
        /// <param name="expiration">Cache Expiration</param>
        public void SetItem<T>(string key, T value, DateTimeOffset expiration)
            => _cache.Set(key, value, expiration);

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
            if (TryGetValue(key, out TItem item))
            {
                return item;
            }

            return await CreateAsyncLazyWithLock(key, factory);
        }
        
        [ExcludeFromCodeCoverage]
        private AsyncLazy<TItem> CreateAsyncLazyWithLock<TItem>(string key, Func<Task<CacheResult<TItem>>> factory)
        {
            var asyncKey = CreateAsyncKey(key);
            
            if (TryGetValue(asyncKey, out AsyncLazy<TItem> asyncItem))
            {
                return asyncItem;
            }
            
            var lockStr = string.Intern("mutex_" + asyncKey);

            lock (lockStr)
            {
                if (TryGetValue(asyncKey, out asyncItem))
                {
                    return asyncItem;
                }
                
                if (TryGetValue(key, out TItem item))
                {
                    return new AsyncLazy<TItem>(() => item);
                }

                asyncItem = new AsyncLazy<TItem>(() => CreateLazyFactory(key, factory));
                
                _cache.Set(asyncKey, asyncItem);
            }

            return asyncItem;
        }
        
        private async Task<TItem> CreateLazyFactory<TItem>(string key,  Func<Task<CacheResult<TItem>>> factory)
        {
            try
            {
                var result = await factory().ConfigureAwait(false);
            
                if (!result.ShouldCache)
                {
                    return result.Result;
                }
                
                using var entry = _cache.CreateEntry(key);
                entry.AbsoluteExpiration =  DateTimeOffset.UtcNow + result.AbsoluteCacheDuration;
                entry.SetValue(result.Result);
                return result.Result;
            }
            finally
            {
                var asyncKey = CreateAsyncKey(key);
                _cache.Remove(asyncKey);
            }
            
        }
        
        private string CreateAsyncKey(string key) => $"{key}-async";
        
    }
}
