using System;
using System.Threading.Tasks;
using System.Web;
using Medidata.MAuth.Core;
using Medidata.MAuth.HttpModule.Configurations;

namespace Medidata.MAuth.HttpModule
{
    public class MAuthAuthenticationModule : IHttpModule
    {
        private readonly MAuthAuthenticationModuleOptions options;

        public MAuthAuthenticationModule()
            : this(new MAuthHttpModuleConfig())
        {
        }

        public MAuthAuthenticationModule(IMAuthHttpModuleConfig config)
        {
            options = config.GetMAuthAuthenticationModuleOptions();
        }

        public void Init(HttpApplication context)
        {
            var wrapper = new EventHandlerTaskAsyncHelper(AuthenticateRequest);
            context.AddOnAuthenticateRequestAsync(wrapper.BeginEventHandler, wrapper.EndEventHandler);
        }

        private async Task AuthenticateRequest(object sender, System.EventArgs e)
        {
            var httpApplication = (HttpApplication)sender;
            var request = httpApplication.Context.GetRequestForContext();
            var response = httpApplication.Context.GetResponseForContext();

            // check if path is exempted for authencation
            if (request.PathIsIn(options.MAuthExceptionPaths))
                return;

            var authenticator = new MAuthAuthenticator(options);
            try
            {
                if (await authenticator.AuthenticateRequest(request))
                    return;
            }
            catch (Exception)
            {
                if (!options.HideExceptionsAndReturnUnauthorized)
                    throw;
            }

            response.StatusCode = 403;
            response.End();
        }

        public void Dispose()
        {
        }
    }
}
