using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Owin;
using ILogger = Microsoft.Owin.Logging.ILogger;

namespace Medidata.MAuth.Owin
{
    internal class MAuthMiddleware: OwinMiddleware
    {
        private readonly MAuthMiddlewareOptions options;
        private readonly MAuthAuthenticator authenticator;

        public MAuthMiddleware(OwinMiddleware next, MAuthMiddlewareOptions options, ILogger owinLogger) : base(next)
        {
            this.options = options;
            Microsoft.Extensions.Logging.ILogger logger = new OwinLoggerWrapper(owinLogger); 
            authenticator = new MAuthAuthenticator(options, logger);
        }

        public override async Task Invoke(IOwinContext context)
        {
            await context.EnsureRequestBodyStreamSeekable();
            if (!options.Bypass(context.Request) &&
                !await context.TryAuthenticate(authenticator, options.HideExceptionsAndReturnUnauthorized))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return;
            }

            context.Request.Body.Rewind();

            await Next.Invoke(context);
        }
    }
}
