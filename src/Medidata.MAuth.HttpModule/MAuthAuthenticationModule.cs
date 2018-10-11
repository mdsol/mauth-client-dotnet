using System;
using System.Collections.Specialized;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Medidata.MAuth.Core;
using Medidata.MAuth.HttpModule.Configurations;

namespace Medidata.MAuth.HttpModule
{
    /// <summary>
    /// TODO..
    /// </summary>
    public class MAuthAuthenticationModule : IHttpModule
    {
        private readonly MAuthAuthenticationModuleOptions options;

        /// <summary>
        /// TODO..
        /// </summary>
        public MAuthAuthenticationModule()
            : this(new AppsettingsToOptionsGenerator())
        {

        }

        /// <summary>
        /// TODO..
        /// </summary>
        /// <param name="config"></param>
        public MAuthAuthenticationModule(IMAuthHttpModuleOptionsGenerator config)
        {
            options = config.GenerateOptions();
        }

        /// <summary>
        /// TODO..
        /// </summary>
        /// <param name="context"></param>
        public void Init(HttpApplication context)
        {
            var wrapper = new EventHandlerTaskAsyncHelper(AuthenticateRequest);
            context.AddOnAuthenticateRequestAsync(wrapper.BeginEventHandler, wrapper.EndEventHandler);
        }

        private async Task AuthenticateRequest(object sender, EventArgs e)
        {
            var httpApplication = (HttpApplication)sender;
            var request = httpApplication.Context.Request.GetRequestForContext();

            // check if path is exempted for authencation
            if (request.PathIsIn(options.MAuthExceptionPaths))
                return;

            var authenticator = new MAuthAuthenticator(options);
            Exception authenticationException = null;
            try
            {
                if (await authenticator.AuthenticateRequest(request))
                {
                    httpApplication.Context.Request.InputStream.Rewind();
                    return;
                }
            }
            catch (Exception ex)
            {
                authenticationException = ex;
            }

            var response = httpApplication.Context.Response;
            response.StatusCode = (int)HttpStatusCode.Unauthorized;
            WriteErrorResponseMessage(httpApplication.Context, authenticationException);
            response.End();
        }

        private void WriteErrorResponseMessage(HttpContext context, Exception ex = null)
        {
            var writeDetailedError = (!context.IsCustomErrorEnabled) || (!options.HideExceptionsAndReturnUnauthorized);
            context.Response.Write(
                writeDetailedError
                    ? new AuthenticationException(
                        $"Failed to authenticate with mauth. <br/>" +
                        $"Error: {ex.Message} <br/>" +
                        $"This server MAuth Uuid: {options.ApplicationUuid} <br/>" +
                        $"MAuth server Url: {options.MAuthServiceUrl} <br/>" +
                        $"The Following headers were recieved:{FormatCollection(context.Request.Headers)} <br />", ex)
                    : new AuthenticationException("Failed to authenticate with mauth."));
        }

        private string FormatCollection(NameValueCollection collection)
        {
            var sb = new StringBuilder();
            sb.Append("<table>");
            foreach (var key in collection.AllKeys)
            {
                sb.AppendFormat("<tr><td>{0}</td><td>{1}</td></tr>", key, collection[key]);
            }
            sb.Append("</table>");

            return sb.ToString();
        }

        /// <summary>
        /// TODO..
        /// </summary>
        public void Dispose()
        {
        }
    }
}
