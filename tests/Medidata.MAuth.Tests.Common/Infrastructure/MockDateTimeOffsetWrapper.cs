using System;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.Tests.Common.Infrastructure
{
    public class MockDateTimeOffsetWrapper : IDateTimeOffsetWrapper
    {
        public DateTimeOffset MockedValue { get; set; }

        public DateTimeOffset GetUtcNow() => MockedValue;
    }
}
