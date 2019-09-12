using System;
using Microsoft.Owin.Logging;
using Owin;

namespace Medidata.MAuth.Owin
{
    /// <summary>
    /// Extension methods to add MAuth authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class MAuthAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="MAuthMiddleware" /> middleware to the specified <see cref="IAppBuilder"/>, which
        /// enables MAuth authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder" /> to add the middleware to.</param>
        /// <param name="options">
        /// A <see cref="MAuthMiddlewareOptions"/> that specifies the options for the middleware.
        /// </param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IAppBuilder UseMAuthAuthentication(this IAppBuilder app, MAuthMiddlewareOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var owinLogger = app.CreateLogger<MAuthMiddleware>();
            return app.Use<MAuthMiddleware>(options, owinLogger);
        }

        /// <summary>
        /// Adds the <see cref="MAuthMiddleware"/> middleware to the specified <see cref="IAppBuilder"/>, which
        /// enables MAuth authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> to add the middleware to.</param>
        /// <param name="configureOptions">An action delegate to configure the provided
        /// <see cref="MAuthMiddlewareOptions"/>.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IAppBuilder UseMAuthAuthentication(
            this IAppBuilder app, Action<MAuthMiddlewareOptions> configureOptions)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            var options = new MAuthMiddlewareOptions();

            configureOptions?.Invoke(options);

            return app.UseMAuthAuthentication(options);
        }
    }
}
