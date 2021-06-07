using Newtonsoft.Json;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class UnSignedRequest
    {
        [JsonProperty(PropertyName = "verb")]
        public string Verb { get; set; }

        [JsonProperty(PropertyName = "url")]
        public string Url { get; set; }

        [JsonProperty(PropertyName = "body")]
        public string Body { get; set; }

        [JsonProperty(PropertyName = "body_filepath")]
        public string BodyFilePath { get; set; }
    }
}
