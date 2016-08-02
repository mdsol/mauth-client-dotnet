using Medidata.MAuth.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Medidata.MAuth.Tests
{
    internal class AssertSigningHandler : HttpMessageHandler
    {
        public string MAuthHeader { get; private set; }

        public long MAuthTimeHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            MAuthHeader = request.Headers.GetFirstValueOrDefault<string>(Constants.MAuthHeaderKey);
            MAuthTimeHeader = request.Headers.GetFirstValueOrDefault<long>(Constants.MAuthTimeHeaderKey);

            return Task.Run(() => new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
