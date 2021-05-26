using Newtonsoft.Json;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class AuthenticationHeader
    {
        [JsonProperty(PropertyName = "MCC-Authentication")]
        public string MccAuthentication { get; set; }

        [JsonProperty(PropertyName = "MCC-Time")]
        public long MccTime { get; set; }

    }
}
