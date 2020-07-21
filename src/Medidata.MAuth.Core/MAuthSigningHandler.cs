using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Medidata.MAuth.Core.Exceptions;
using Medidata.MAuth.Core.Models;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// A HTTP message handler to sign an outgoing <see cref="HttpRequestMessage"/> with the MAuth-specific
    /// authentication information.
    /// </summary>
    public class MAuthSigningHandler: DelegatingHandler
    {
        private readonly MAuthSigningOptions options;
        private IMAuthCore mAuthCore;

        /// <summary>Gets the Uuid of the client application.</summary>
        public Guid ClientAppUuid => options.ApplicationUuid;

        /// <summary>
        /// Initializes a new instance of the <see cref="MAuthSigningHandler"/> class with the provided
        /// <see cref="MAuthSigningOptions"/>.
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        public MAuthSigningHandler(MAuthSigningOptions options)
        {
            this.options = options;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MAuthSigningHandler"/> class with the provided
        /// <see cref="MAuthSigningOptions"/> and an inner <see cref="HttpMessageHandler"/>. 
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        /// <param name="innerHandler">
        /// The inner handler which is responsible for processing the HTTP response messages.
        /// </param>
        public MAuthSigningHandler(MAuthSigningOptions options, HttpMessageHandler innerHandler): base(innerHandler)
        {
            this.options = options;
        }

        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information and sends the request to the
        /// inner handler to send to the server as an asynchronous operation.
        /// </summary>
        /// <param name="request">The HTTP request message to sign and send to the server.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>Returns <see cref="Task{HttpResponseMessage}"/>. The task object representing the asynchronous
        /// operation.</returns>
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (InnerHandler == null)
                InnerHandler = new HttpClientHandler();

            var mauthVersions = GetMAuthSigningVersions(options.SignVersions);
            foreach(var version in mauthVersions)
            {
                var mAuthCore = MAuthCoreFactory.Instantiate(version);
                request = await mAuthCore.Sign(request, options).ConfigureAwait(false);
            }

            return await base
                .SendAsync(request, cancellationToken)
                .ConfigureAwait(continueOnCapturedContext: false);
        }

        private IEnumerable<MAuthVersion> GetMAuthSigningVersions(string signingVersions)
        {
            if (string.IsNullOrEmpty(signingVersions))
                return new List<MAuthVersion>() { MAuthVersion.MWSV2 };

            var mauthVersions = new List<MAuthVersion>();
            var signingArray = signingVersions.ToLower().Split(',');

            foreach (var item in signingArray)
            {
                switch (item.Trim())
                {
                    case "v1":
                        mauthVersions.Add(MAuthVersion.MWS);
                        break;
                    case "v2":
                        mauthVersions.Add(MAuthVersion.MWSV2);
                        break;
                }
            }

            if (signingArray.Any() && !mauthVersions.Any())
                throw new InvalidVersionException($"Signing with {signingVersions} version is not allowed.");

            return mauthVersions;
        }
    }
}
