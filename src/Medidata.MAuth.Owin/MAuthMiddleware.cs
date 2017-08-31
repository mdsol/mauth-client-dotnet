using System.IO;
using System.Net;
using System.Threading.Tasks;
using Medidata.MAuth.Core;
using Microsoft.Owin;

namespace Medidata.MAuth.Owin
{
    internal class MAuthMiddleware: OwinMiddleware
    {
        private readonly MAuthMiddlewareOptions options;
        private readonly MAuthAuthenticator authenticator;

        public MAuthMiddleware(OwinMiddleware next, MAuthMiddlewareOptions options): base(next)
        {
            this.options = options;
            authenticator = new MAuthAuthenticator(options);
        }

        public override async Task Invoke(IOwinContext context)
        {
            await context.EnsureRequestBodyStreamSeekable();

            if (!options.Bypass(context.Request) &&
                !await context.TryAuthenticate(authenticator, options.HideExceptionsAndReturnForbidden))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return;
            }

            if (context.Request.Body.CanSeek)
                context.Request.Body.Seek(0, SeekOrigin.Begin);

            await Next.Invoke(context);
        }
    }
}
