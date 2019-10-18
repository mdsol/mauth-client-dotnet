using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.Tests.Infrastructure
{
    internal class AssertSigningHandler : HttpMessageHandler
    {
        public string MAuthHeader { get; private set; }

        public string MAuthTimeHeader { get; private set; }

        public string MAuthHeaderV2 { get; private set; }

        public string MAuthTimeHeaderV2 { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            MAuthHeaderV2 = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2);
            MAuthHeader   = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);

            MAuthTimeHeaderV2 = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthTimeHeaderKeyV2);
            MAuthTimeHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthTimeHeaderKey);

            return Task.Run(() => new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}