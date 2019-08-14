using System;
using Microsoft.AspNetCore.Builder;

namespace Medidata.MAuth.AspNetCore
{
    /// <summary>
    /// Extension methods to add MAuth authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class MAuthAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="MAuthMiddleware" /> middleware to the specified <see cref="IApplicationBuilder"/>,
        /// which enables MAuth authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to add the middleware to.</param>
        /// <param name="options">
        /// A <see cref="MAuthMiddlewareOptions"/> that specifies the options for the middleware.
        /// </param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseMAuthAuthentication(this IApplicationBuilder app,
            MAuthMiddlewareOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (options == null)
                throw new ArgumentNullException(nameof(options));


            return app.UseMiddleware<MAuthMiddleware>(options);
        }

        /// <summary>
        /// Adds the <see cref="MAuthMiddleware"/> middleware to the specified <see cref="IApplicationBuilder"/>,
        /// which enables MAuth authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <param name="configureOptions">An action delegate to configure the provided
        /// <see cref="MAuthMiddlewareOptions"/>.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseMAuthAuthentication(
            this IApplicationBuilder app, Action<MAuthMiddlewareOptions> configureOptions)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            var options = new MAuthMiddlewareOptions();

            configureOptions?.Invoke(options);

            return app.UseMAuthAuthentication(options);
        }
    }
}
