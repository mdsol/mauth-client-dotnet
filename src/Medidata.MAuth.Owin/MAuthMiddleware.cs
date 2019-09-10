using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Owin;

namespace Medidata.MAuth.Owin
{
    internal class MAuthMiddleware: OwinMiddleware
    {
        private readonly MAuthMiddlewareOptions options;
        private readonly MAuthAuthenticator authenticator;
        private Microsoft.Extensions.Logging.ILogger _logger;

        public MAuthMiddleware(OwinMiddleware next, MAuthMiddlewareOptions options, IAppBuilder app) : base(next)
        {
            this.options = options;
            var owinLogger = app.CreateLogger<MAuthMiddleware>();
            this._logger = new OwinLoggerWrapper(owinLogger); 
            authenticator = new MAuthAuthenticator(options, _logger);
        }

        public override async Task Invoke(IOwinContext context)
        {
            _logger.LogInformation("hello");
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
