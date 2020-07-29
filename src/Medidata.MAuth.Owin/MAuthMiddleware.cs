using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Owin;
using ILogger = Microsoft.Owin.Logging.ILogger;

namespace Medidata.MAuth.Owin
{
    internal class MAuthMiddleware: OwinMiddleware
    {
        private readonly MAuthMiddlewareOptions _options;
        private readonly MAuthAuthenticator _authenticator;

        public MAuthMiddleware(OwinMiddleware next, MAuthMiddlewareOptions options, ILogger owinLogger) : base(next)
        {
            _options = options;
            Microsoft.Extensions.Logging.ILogger logger = new OwinLoggerWrapper(owinLogger); 
            _authenticator = new MAuthAuthenticator(options, logger);
        }

        public override async Task Invoke(IOwinContext context)
        {
            await context.EnsureRequestBodyStreamSeekable().ConfigureAwait(false);
            if (!_options.Bypass(context.Request) &&
                !await context.TryAuthenticate(_authenticator, _options.HideExceptionsAndReturnUnauthorized)
                .ConfigureAwait(false))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return;
            }

            context.Request.Body.Rewind();

            await Next.Invoke(context).ConfigureAwait(false);
        }
    }
}
