using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// A HTTP message handler to sign an outgoing <see cref="HttpRequestMessage"/> with the MAuth-specific
    /// authentication information.
    /// </summary>
    public class MAuthSigningHandler: DelegatingHandler
    {
        private readonly MAuthAuthenticator authenticator;

        /// <summary>Gets the Uuid of the client application.</summary>
        public Guid ClientAppUuid => authenticator.ApplicationUuid;

        /// <summary>
        /// Initializes a new insance of the <see cref="MAuthSigningHandler"/> class with the provided
        /// <see cref="MAuthOptions"/>.
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        public MAuthSigningHandler(MAuthOptions options): this(options, new HttpClientHandler()) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="MAuthSigningHandler"/> class with the provided
        /// <see cref="MAuthOptions"/> and an inner <see cref="HttpMessageHandler"/>. 
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        /// <param name="innerHandler">
        /// The inner handler which is responsible for processing the HTTP response messages.
        /// </param>
        public MAuthSigningHandler(MAuthOptions options, HttpMessageHandler innerHandler): base(innerHandler)
        {
            authenticator = new MAuthAuthenticator(options);
        }

        /// <summary>
        /// Signs an HTTP request with the MAuth-specific authentication information and sends the request to the
        /// inner handler to send to the server as an asynchronous operation.
        /// </summary>
        /// <param name="request">The HTTP request message to sign and send to the server.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>Returns <see cref="Task{HttpResponseMessage}"/>. The task object representing the asynchronous
        /// operation.</returns>
        protected async override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return await base
                .SendAsync(await authenticator.SignRequest(request), cancellationToken)
                .ConfigureAwait(continueOnCapturedContext: false);
        }
    }
}
