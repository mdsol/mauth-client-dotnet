using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Owin;

namespace Medidata.MAuth.Owin
{
    internal class MAuthMiddleware: OwinMiddleware
    {
        private readonly MAuthMiddlewareOptions options;
        private readonly MAuthAuthenticator authenticator;

        public MAuthMiddleware(OwinMiddleware next, MAuthMiddlewareOptions options) : base(next)
        {
            this.options = options;
            authenticator = new MAuthAuthenticator(options, NullLoggerFactory.Instance);
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
