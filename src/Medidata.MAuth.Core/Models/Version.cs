using System.Runtime.Serialization;

namespace Medidata.MAuth.Core.Models
{
    /// <summary>
    /// 
    /// </summary>
    public enum Version
    {
        /// <summary>
        /// 
        /// </summary>
        [EnumMember(Value = "MWS")]
        MWS = 0,
        /// <summary>
        /// 
        /// </summary>
        [EnumMember(Value = "MWSV2")]
        MWSV2 = 1,
    }
}
