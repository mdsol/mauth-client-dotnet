using System;
using System.Runtime.Serialization;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.Tests.Infrastructure
{
    [DataContract]
    internal class RequestData
    {
        [DataMember]
        public Uri Url { get; set; }

        [DataMember]
        public string Method { get; set; }

        [DataMember]
        public DateTimeOffset SignedTime { get; set; }

        [DataMember]
        public string Base64Content { get; set; }

        [DataMember]
        public Guid ApplicationUuid { get; set; }

        [DataMember]
        public string Payload { get; set; }

        [IgnoreDataMember]
        public long SignedTimeUnixSeconds => SignedTime.ToUnixTimeSeconds();

        [IgnoreDataMember]
        public string MAuthHeader => $"MWS {ApplicationUuidString}:{Payload}";

        [IgnoreDataMember]
        public string ApplicationUuidString => ApplicationUuid.ToHyphenString();

        [IgnoreDataMember]
        public string MAuthHeaderV2 => $"MWSV2 {ApplicationUuidString}:{Payload};";
    }
}
