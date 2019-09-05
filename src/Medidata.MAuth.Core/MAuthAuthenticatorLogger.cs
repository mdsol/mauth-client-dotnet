using Microsoft.Extensions.Logging;
using System;
using log4net;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Medidata.MAuth.Core
{
    /// <summary>
    /// MAuthAuthenticatorLogger Class which exposes logging methods used for MAuthenticator
    /// </summary>
    internal class MAuthAuthenticatorLogger
    {
        private readonly log4net.ILog _log;

        private readonly ILogger _logger;
        public MAuthAuthenticatorLogger(ILog logger)
        {
            _log = logger;
        }

        public MAuthAuthenticatorLogger(ILogger logger)
        {
            _logger = logger;
        }

        /* 
         * Extremely boring code ahead 
         */

        #region This code is extremely dull

        public void LogWarning(Exception exception, string message)
        {
            if (_log is null)
            {
                _logger.LogWarning(exception, message);
            }
            else
            { _log.Warn(message, exception);}
        }

        public void LogInformation(string message)
        {
            if (_log is null)
            {
                _logger.LogInformation(message);
            }
            else
            { _log.Info(message);}
        }

        public void LogError(Exception exception, string message)
        {
            if (_log is null)
            {
                _logger.LogError(exception, message);
            }
            else
            { _log.Error(message, exception);}
        }
        #endregion

    }
}
