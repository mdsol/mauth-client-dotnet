using System;

namespace Medidata.MAuth.Core;

/// <summary>
/// A facade for <see cref="DateTimeOffset" /> 
/// </summary>
public interface IDateTimeOffsetWrapper
{
    /// <summary>
    /// A facade for the UtcNow property.
    /// </summary>
    /// <returns>A <see cref="DateTimeOffset" /> value</returns>
    DateTimeOffset GetUtcNow();
}
