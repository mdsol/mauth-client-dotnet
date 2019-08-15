using Medidata.MAuth.Core.Exceptions;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    internal class MAuthCoreFactory
    {
        public static IMAuthCore Instantiate(MAuthVersion version = MAuthVersion.MWS)
        {
            if (version == MAuthVersion.MWSV2)
                return new MAuthCoreV2();
            else if (version == MAuthVersion.MWS)
                return new MAuthCore();

            throw new InvalidVersionException($"Version is not recognized:{version}");
        }
    }
}
