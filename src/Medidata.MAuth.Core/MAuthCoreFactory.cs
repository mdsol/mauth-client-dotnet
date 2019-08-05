using System;
using Version = Medidata.MAuth.Core.Models.Version;

namespace Medidata.MAuth.Core
{
    internal class MAuthCoreFactory
    {
        public static IMAuthCore Instantiate(string version = "MWS")
        {
            if (version == Version.MWSV2.ToString())
                return new MAuthCoreV2();
            else if (version == Version.MWS.ToString())
                return new MAuthCore();

            throw new Exception("Version is not recognized");
        }
    }
}
