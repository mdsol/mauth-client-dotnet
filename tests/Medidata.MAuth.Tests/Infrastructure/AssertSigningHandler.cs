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

        public long MAuthTimeHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            MAuthHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKeyV2) ?? 
                          request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);

            var timeHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthTimeHeaderKeyV2) ??
                             request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthTimeHeaderKey);

            MAuthTimeHeader = long.Parse(timeHeader);

            return Task.Run(() => new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
