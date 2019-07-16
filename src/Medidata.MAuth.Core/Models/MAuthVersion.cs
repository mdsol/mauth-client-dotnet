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
        [EnumMember(Value = "V1")]
        V1 = 0,
        /// <summary>
        /// 
        /// </summary>
        [EnumMember(Value = "V2")]
        V2 = 1,
    }
}
