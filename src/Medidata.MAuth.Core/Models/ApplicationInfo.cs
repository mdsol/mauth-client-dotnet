using System;
using Newtonsoft.Json;

namespace Medidata.MAuth.Core
{
    internal class ApplicationInfo
    {
        [JsonProperty("app_name")]
        public string Name { get; set; }

        [JsonProperty("app_uuid")]
        public Guid Uuid { get; set; }

        [JsonProperty("public_key_str")]
        public string PublicKey { get; set; }

        [JsonProperty("created_at")]
        public DateTimeOffset CreationDate { get; set; }
    }
}
