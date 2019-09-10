using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Logging;
using ILogger = Microsoft.Owin.Logging.ILogger;

namespace Medidata.MAuth.Owin
{
    internal class OwinLoggerWrapper : Microsoft.Extensions.Logging.ILogger
    {
        private readonly ILogger _owinLogger;

        public OwinLoggerWrapper(ILogger owinLogger)
        {
            _owinLogger = owinLogger;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            throw new NotImplementedException();
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            switch (logLevel)
            {
                case LogLevel.Critical:
                    return _owinLogger.IsEnabled(TraceEventType.Critical);
                case LogLevel.Debug:
                case LogLevel.Trace:
                case LogLevel.Information:
                    return _owinLogger.IsEnabled(TraceEventType.Information);
                case LogLevel.Error:
                    return _owinLogger.IsEnabled(TraceEventType.Error);
                case LogLevel.Warning:
                    return _owinLogger.IsEnabled(TraceEventType.Warning);
                default:
                    throw new ArgumentOutOfRangeException(nameof(logLevel));
            }
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            if (formatter == null)
            {
                throw new ArgumentNullException(nameof(formatter));
            }
            string message = null;
            if (null != formatter)
            {
                message = formatter(state, exception);
            }
            if (!string.IsNullOrEmpty(message) || exception != null)
            {
                switch (logLevel)
                {
                    case LogLevel.Critical:
                        _owinLogger.WriteCritical(message, exception);
                        break;
                    case LogLevel.Debug:
                    case LogLevel.Trace:
                    case LogLevel.Error:
                        _owinLogger.WriteError(message, exception);
                        break;
                    case LogLevel.Information:
                        _owinLogger.WriteInformation(message);
                        break;
                    case LogLevel.Warning:
                        _owinLogger.WriteWarning(message, exception);
                        break;
                    default:
                        _owinLogger.WriteWarning($"Encountered unknown log level {logLevel}, writing out as Info.");
                        _owinLogger.WriteInformation(message);
                        break;
                }
            }
        }
    }
}
