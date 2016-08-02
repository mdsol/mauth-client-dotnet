using System;

namespace Medidata.MAuth.Core
{
    internal abstract class AuthenticationInfo
    {
        public Guid ApplicationUuid { get; set; }

        public DateTimeOffset SignedTime { get; set; }
    }
}
