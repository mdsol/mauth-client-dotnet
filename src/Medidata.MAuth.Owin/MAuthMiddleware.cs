using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Text;
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

            await Next.Invoke(context);
        }
    }
}
