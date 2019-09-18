using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Medidata.MAuth.AspNetCore
{
    /// <summary>
    /// Enables the middleware for the aspnet core applications.
    /// </summary>
    internal class MAuthMiddleware
    {
        private readonly MAuthMiddlewareOptions options;
        private readonly MAuthAuthenticator authenticator;
        private readonly RequestDelegate next;

        /// <summary>
        /// Creates a new <see cref="MAuthMiddleware"/>
        /// </summary>
        /// <param name="next">The <see cref="RequestDelegate"/> representing the next middleware in the pipeline.</param>
        /// <param name="options">The <see cref="MAuthMiddlewareOptions"/> representing the options for the middleware.</param>
        /// <param name="loggerFactory">The <see cref="ILoggerFactory"/> representing the factory that used to create logger instances.</param>
        public MAuthMiddleware(RequestDelegate next, MAuthMiddlewareOptions options, ILoggerFactory loggerFactory)
        {
            this.next = next;
            this.options = options;
            loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
            ILogger logger = loggerFactory.CreateLogger<MAuthMiddleware>();
            this.authenticator = new MAuthAuthenticator(options, logger); 
        }

        /// <summary>
        /// Invokes the logic of the middleware.
        /// </summary>
        /// <param name="context"> The <see cref="HttpContext"/>.</param>
        /// <returns>A <see cref="Task"/> that completes when the middleware has completed processing.</returns>
        public async Task Invoke(HttpContext context)
        {
            context.Request.EnableRewind();

            if (!options.Bypass(context.Request) &&
                !await context.TryAuthenticate(authenticator, options.HideExceptionsAndReturnUnauthorized))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return;
            }

            context.Request.Body.Rewind();

            await next.Invoke(context);
        }
    }
}
