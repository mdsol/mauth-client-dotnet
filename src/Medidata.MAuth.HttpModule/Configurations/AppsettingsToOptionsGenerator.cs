using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace Medidata.MAuth.HttpModule.Configurations
{
    /// <summary>
    /// TODO..
    /// </summary>
    public class AppsettingsToOptionsGenerator : IMAuthHttpModuleOptionsGenerator
    {
        /// <summary>
        /// TODO...
        /// </summary>
        /// <returns></returns>
        public MAuthAuthenticationModuleOptions GenerateOptions()
        {
            return new MAuthAuthenticationModuleOptions
            {
                PrivateKey = Get("mAuthPrivateKeyPath"),
                MAuthServiceUrl = new Uri(Get("mAuthServiceEndpoint")),
                ApplicationUuid = new Guid(Get("mAuthUuid")),
                HideExceptionsAndReturnUnauthorized =
                    bool.TryParse(Get("mAuthHideExceptionsAndReturnUnauthorized"), out bool hideExceptionsAndReturnUnauthorized) ?
                    hideExceptionsAndReturnUnauthorized : true,
                MAuthExceptionPaths = GetList("mAuthWhitelist")
            };
        }

        private static IEnumerable<string> GetList(string key)
        {
            var result = new List<string>();

            var value = ConfigurationManager.AppSettings[key];
            if (!string.IsNullOrWhiteSpace(value))
            {
                result.AddRange(value.Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries).Select(w => w.Trim()).ToList());
            }

            return result;
        }

        private static string Get(string key)
        {
            return ConfigurationManager.AppSettings[key];
        }
    }
}
