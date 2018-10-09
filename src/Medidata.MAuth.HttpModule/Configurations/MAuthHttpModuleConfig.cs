using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace Medidata.MAuth.HttpModule.Configurations
{
    public class MAuthHttpModuleConfig : IMAuthHttpModuleConfig
    {
        public MAuthAuthenticationModuleOptions GetMAuthAuthenticationModuleOptions()
        {
            return new MAuthAuthenticationModuleOptions
            {
                PrivateKey = Get("mAuthPrivateKeyPath"),
                MAuthServiceUrl = new Uri(Get("mAuthServiceEndpoint")),
                ApplicationUuid = new Guid(Get("mAuthUuid")),
                HideExceptionsAndReturnUnauthorized =
                    bool.TryParse(Get("mAuthHideExceptionsAndReturnUnauthorized"), out bool hideExceptionsAndReturnUnauthorized) ?
                    hideExceptionsAndReturnUnauthorized : true,
                MAuthExceptionPaths = GetList("mAuthExceptionPaths")
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
