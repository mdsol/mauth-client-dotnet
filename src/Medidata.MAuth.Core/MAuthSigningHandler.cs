using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
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

            if (options.DisableV1 == false) // default
            {
                // Add headers for both V1 and V2
                return await base
                    .SendAsync(await DefaultSign(request, options).ConfigureAwait(false), cancellationToken)
                    .ConfigureAwait(continueOnCapturedContext: false);
            }

            // Signing with only V2
            mAuthCore = MAuthCoreFactory.Instantiate(MAuthVersion.MWSV2);

            return await base
                .SendAsync(await mAuthCore.Sign(request, options).ConfigureAwait(false), cancellationToken)
                .ConfigureAwait(continueOnCapturedContext: false);
        }

        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="opt">The options that contains the required information for the signing.</param>
        /// <returns>
        /// A Task object which will result the request signed with the authentication information when it completes.
        /// </returns>
        private async Task<HttpRequestMessage> DefaultSign(
            HttpRequestMessage request, MAuthSigningOptions opt)
        {
            var authenticationInfo = new PrivateKeyAuthenticationInfo()
            {
                ApplicationUuid = opt.ApplicationUuid,
                SignedTime = opt.SignedTime ?? DateTimeOffset.UtcNow,
                PrivateKey = opt.PrivateKey.Dereference().NormalizeLines()
            };
           var  mAuthCoreV2 = MAuthCoreFactory.Instantiate(MAuthVersion.MWSV2);
           request= await mAuthCoreV2.AddAuthenticationInfo(request, authenticationInfo);

            var mAuthCoreV1= MAuthCoreFactory.Instantiate(MAuthVersion.MWS);
            return await mAuthCoreV1.AddAuthenticationInfo(request, authenticationInfo);
        }
    }
}
