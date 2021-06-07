using Newtonsoft.Json;
using System;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class SigningConfig
    {
        [JsonProperty(PropertyName ="app_uuid")]
        public Guid AppUuid { get; set; }

        [JsonProperty(PropertyName = "request_time")]
        public long RequestTime { get; set; }

        [JsonProperty(PropertyName = "private_key_file")]
        public string PrivateKeyFile { get; set; }

        public string PrivateKey { get; set; }
    }
}
