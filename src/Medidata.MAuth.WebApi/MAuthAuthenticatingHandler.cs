using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Medidata.MAuth.Core;

namespace Medidata.MAuth.WebApi
{
    /// <summary>
    /// A HTTP message handler to authenticate in incoming <see cref="HttpRequestMessage"/> based on its MAuth-specific
    /// authentication information.
    /// </summary>
    public class MAuthAuthenticatingHandler : DelegatingHandler
    {
        private readonly MAuthWebApiOptions options;
        private readonly MAuthAuthenticator authenticator;

        /// <summary>Gets the Uuid of the client application.</summary>
        public Guid ClientAppUuid => authenticator.ApplicationUuid;

        /// <summary>
        /// Initializes a new insance of the <see cref="MAuthAuthenticatingHandler"/> class with the provided
        /// <see cref="MAuthWebApiOptions"/>.
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        public MAuthAuthenticatingHandler(MAuthWebApiOptions options)
        {
            this.options = options;
            authenticator = new MAuthAuthenticator(options);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MAuthAuthenticatingHandler"/> class with the provided
        /// <see cref="MAuthOptionsBase"/> and an inner <see cref="HttpMessageHandler"/>. 
        /// </summary>
        /// <param name="options">The options for this message handler.</param>
        /// <param name="innerHandler">
        /// The inner handler which is responsible for processing the HTTP response messages.
        /// </param>
        public MAuthAuthenticatingHandler(MAuthWebApiOptions options, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            this.options = options;
            authenticator = new MAuthAuthenticator(options);
        }

        /// <summary>
        /// Authenticates an HTTP request with the MAuth-specific authentication information and sends the request to
        /// the inner handler as an asynchronous operation.
        /// </summary>
        /// <param name="request">The HTTP request message to authenticate and send to inner handler.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>Returns <see cref="Task{HttpResponseMessage}"/>. The task object representing the asynchronous
        /// operation.</returns>
        protected async override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (InnerHandler == null)
                InnerHandler = new HttpClientHandler();

            if (!await request.TryAuthenticate(authenticator, options.HideExceptionsAndReturnForbidden))
                return new HttpResponseMessage(HttpStatusCode.Forbidden) { RequestMessage = request };

            return await base
                .SendAsync(request, cancellationToken)
                .ConfigureAwait(continueOnCapturedContext: false);
        }
    }
}
