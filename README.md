# Medidata.MAuth

Medidata.MAuth is a framework that provides support for authenticating web services and applications
with the Medidata HMAC protocol, MAuth.

## Build Status

| Build | Status |
| --- | --- |
| AppVeyor Release | ![Release](https://ci.appveyor.com/api/projects/status/94450nsec4kwhjpo?branch=master&svg=true) |
| AppVeyor Prerelease | ![Prerelease](https://ci.appveyor.com/api/projects/status/94450nsec4kwhjpo?branch=develop&svg=true) |

## What is MAuth?

The MAuth protocol provides a fault-tolerant, service-to-service authentication scheme for Medidata and third-party
applications that use web services to communicate. The Authentication Service and integrity algorithm is based on
digital signatures encrypted and decrypted with a private/public key pair.

The Authentication Service has two responsibilities. It provides message integrity and provenance validation by
verifying a message sender's signature; its other task is to manage public keys. Each public key is associated with
an application and is used to authenticate message signatures. The private key corresponding to the public key in the
Authentication Service is stored by the application making a signed request; the request is encrypted with this
private key. The Authentication Service has no knowledge of the application's private key, only its public key.

## Medidata.MAuth Components

The framework is divided into separate semi-dependent NuGet packages to provide only the functionality which you need
in your application. Below you can find the description of each individual packages.

### Medidata.MAuth.Core

A core package for the MAuth protocol. This package contains the core functionality which used by the other MAuth
authentication protocol-specific components. This package also can be used standalone if you want to sign HTTP/HTTPS
requests with Medidata MAuth keys using the .NET _HttpClient_ message handler mechanism.

The package recommended in client applications where the application is required to issue MAuth-signed requests to an
MAuth-enabled service.

### Medidata.MAuth.Owin

This package contains an OWIN middleware to validate signed HTTP requests with the Medidata MAuth protocol.
The middleware communicates with an MAuth server in order to confirm the validity of the request authentication header.

Include this package in your OWIN-enabled application if you want to authenticate the incoming requests signed with
the MAuth protocol.

### Medidata.MAuth.AspNetCore

Similar to the [Owin package](#Medidata-MAuth-Owin) this package has the ASP.NET Core-specific middleware that
validates signed HTTP requests incoming to the application.

You can add this package in your ASP.NET Core web api application if you would like to authenticate your incoming
requests signed with the MAuth protocol.

### Medidata.MAuth.WebApi

The package contains an HTTP message handler to validate signed HTTP requests with the Medidata MAuth protocol.
The handler communicates with an MAuth server in order to confirm the validity of the request authentication header.

Include this package in your WebAPI application if you want to authenticate the incoming requests signed with
the MAuth protocol.

## Get Started

Below you can find some information and examples on getting started using the framework.

### Installation

Depending on your needs you can install either the Core package only (for signing requests), or the Owin or WebApi
packages as well if you want to authenticate incoming requests.

The installation is as usual with NuGet.

For signing:

```
nuget install Medidata.MAuth.Core
```

Or in case of the authenticating, either

```
nuget install Medidata.MAuth.Owin
```

or

```
nuget install Medidata.MAuth.WebApi
```

For all of these you can use the _Visual Studio Package Manager_ as well.

The Owin, AspNetCore and WebApi packages are dependent on the Core package, therefore it will be installed automatically in those
cases.

### Signing Outgoing Requests

In order to sign outgoing requests, an `MAuthSigningHandler` class is provided in the Core package. This handler
accepts an `MAuthSigningOptions` instance which stores all the necessary settings for the signing process.

An example:

```C#
using Medidata.MAuth.Core;
using Medidata.MAuth.Core.Models;

public async Task<HttpResponseMessage> SignAndSendRequest(HttpRequestMessage request)
{
    var signingHandler = new MAuthSigningHandler(new MAuthSigningOptions()
    {
        ApplicationUuid = new Guid("7c872d75-986b-4c61-bb17-f2569d42bfb0"),

        // The following can be either a path to the key file or the contents of the file itself
        PrivateKey = "ClientPrivateKey.pem",

        // Enumerations of signing protocols, if not provided defaults to `MAuthVersion.MWS`for sign-in.
        SignVersions = MAuthVersion.MWS | MAuthVersion.MWSV2
    });

    using (var client = new HttpClient(signingHandler))
    {
        return await client.SendAsync(request);
    }
}
```
The `SignVersions` parameter can be used to specify which protocol version to sign outgoing requests. Like as:  
`SignVersions = MAuthVersion.MWS`: signs with `MWS` protocol only.  
`SignVersions = MAuthVersion.MWS | MAuthVersion.MWSV2` : signs with both `MWS` and `MWSV2` protocol.  
If not supplied, it sign by `MWS` protocol by default.

Signing with `MWSV2` protocol supports query string.

The example above is creating a new instance of a `HttpClient` with the handler responsible for signing the
requests and sends the request to its designation. Finally it returns the response from the remote server.

The `MAuthSigningOptions` has the following properties to determine the required settings:

| Name | Description |
| ---- | ----------- |
| **ApplicationUuid** | Determines the unique identifier of the client application used for the MAuth service authentication requests.  This uuid needs to be registered with the MAuth Server in order for the authenticating server application to be able to authenticate the signed request. |
| **PrivateKey** | Determines the RSA private key of the client for signing a request. This key must be in a PEM ASN.1 format. The value of this property can be set as a valid path to a readable key file as well. |
| **SignVersions** | (optional) Enumerations of MAuth protocol versions to sign requests. If not supplied, defaults to `MWS`.

### Authenticating Incoming Requests with the OWIN and ASP.NET Core Middlewares

If your application implements the OWIN-specific or ASP.NET Core pipeline, you can wire in the `MAuthMiddleware`
provided by the Owin and AspNetCore NuGet packages.

The setting and usage is as follows in case of OWIN (in the application's `Startup` class):

With the update of MAuth V2 protocol, the authentication will first check for mauth header with `MWSV2` and if not found then only fallback to authenticate for `MWS` version.
Also, there is options of `DisableV1`, which is `false` by default and when we are ready to disable authentication of V1 protocl i.e. `MWS` version, then we need to pass this option too as `true`.

```C#
using Medidata.MAuth.Owin;

public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        app.UseMAuthAuthentication(options =>
        {
            options.ApplicationUuid = new Guid("a419de8f-d759-4db9-b9a7-c2cd14174987");
            options.MAuthServiceUrl = new Uri("https://mauth.imedidata.com");
            options.AuthenticateRequestTimeoutSeconds = 3;
            options.MAuthServiceRetryPolicy = MAuthServiceRetryPolicy.RetryOnce;
            options.HideExceptionsAndReturnUnauthorized = true;
            options.PrivateKey = "ServerPrivateKey.pem";
            options.Bypass = (request) => request.Uri.AbsolutePath.StartsWith("/allowed");

            // when ready to disable authentication of V1 protococl
            options.DisableV1 = true;
        });
    }
}
```
For enabling the logging from Owin application, the following configuration will need to be added or updated:
```C#
<configuration>
  <system.diagnostics>
    <switches>
      <add name="Microsoft.Owin" value="Information, Error, Warning" />
    </switches>
  </system.diagnostics>
</configuration>
```

A similar way can be implemented for ASP.NET Core (also in the `Startup` class):

```C#
using Medidata.MAuth.AspNetCore;

public class Startup
{
    public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
    {
        app.UseMAuthAuthentication(options =>
        {
            options.ApplicationUuid = new Guid("a419de8f-d759-4db9-b9a7-c2cd14174987");
            options.MAuthServiceUrl = new Uri("https://mauth.imedidata.com");
            options.AuthenticateRequestTimeoutSeconds = 3;
            options.MAuthServiceRetryPolicy = MAuthServiceRetryPolicy.RetryOnce;
            options.HideExceptionsAndReturnUnauthorized = true;
            options.PrivateKey = "ServerPrivateKey.pem";
            options.Bypass = (request) => request.Uri.AbsolutePath.StartsWith("/allowed");

            // when ready to disable authentication of V1 protococl
            options.DisableV1 = true;
        });
    }
}
```

The middlewares take an `MAuthMiddlewareOptions` instance to set up the authentication:

| Name | Description |
| ---- | ----------- |
| **ApplicationUuid** | Determines the unique identifier of the server application used for the MAuth service authentication requests. This uuid needs to be registered with the MAuth Server in order to use it. |
| **MAuthServiceUrl** | Determines the endpoint of the MAuth authentication service. This endpoint is used by the authentication process to verify the validity of the signed request. |
| **PrivateKey** | Determines the RSA private key of the server application for the authentication requests. This key must be in a PEM ASN.1 format. The value of this property can be set as a valid path to a readable key file as well. |
| **AuthenticateRequestTimeoutSeconds** | An optional parameter that determines the timeout in seconds for the MAuth authentication request - the MAuth component will try to reach the MAuth server for this duration before it throws an exception. If not specified, the default value will be **3 seconds**. |
| **MAuthServiceRetryPolicy** | The policy for the retry attempts when communicating with the MAuth service. The following policies can be used: `NoRetry` (no retries), `RetryOnce` (one additional attempt), `RetryTwice` (two additional attempts) and `Agressive` (9 additional attempts) - the default value is **RetryOnce**. |
| **HideExceptionsAndReturnUnauthorized** | An optional parameter that determines if the middleware should swallow all exceptions and return an empty HTTP response with a status code Unauthorized (401) in case of any errors (including authentication and validation errors). The default is **true**. |
| **Bypass** | Determines a function which evaluates if a given request should bypass the MAuth authentication. |
| **DisableV1** | Determines the boolean value which controls whether to disable the signing requests with `MAuthVersion.MWS` requests or not. If not supplied, this default value is  `false`. |

The **HideExceptionsAndReturnUnauthorized** parameter is useful (if set to **false**) when you have an exception handler
mechanism (for example a logger) in your middleware pipeline. In this case the MAuth middleware won't swallow the
exceptions but will throw them with full stack trace and details of the problem - as every authentication errors will
throw a `Medidata.MAuth.Core.AuthenticationException` you can still return a Unauthorized (401) HTTP status code in
those cases.
In the other hand, if you don't use any exception handling mechanism, it is recommended to leave this feature disabled
as setting this to **false** can possibly lead to exposing sensitive details about your application and the
authentication process. Leaving this parameter as **true** will result the middleware to return a Unauthorized (401) HTTP
status code for every error without showing any details.

The **Bypass** function takes a `IOwinRequest` in case of OWIN and an `HttpRequest` instance for ASP.NET Core and
should produce **true** as a result, if the given request satisfies the conditions to bypass the authentication;
otherwise it should result **false** therefore an authentication attempt will occur. If no Bypass predicate provided
in the options, every request will be authenticated by default.

When authentication of V1 requests needs to be disabled, then **DisableV1** should be passed as **true**.

### Authenticating Incoming Requests with the WebApi Message Handler

If your application does not use the OWIN or ASP.NET Core middleware infrastructure, but it uses the ASP.NET WebAPI
framework, the WebApi package provides an `MAuthAuthenticatingHandler` which can be assigned to WebAPI routes or
the global handler collection in order to automatically authenticate incoming requests.

For a global registration (that is, use MAuth authentication for all requests), you can register the handler as below
(in your `WebApiConfig` class):

```C#
using Medidata.MAuth.WebApi;

public static class WebApiConfig
{
    public static void Register(HttpConfiguration config)
    {
        var options = new MAuthWebApiOptions()
        {
            ApplicationUuid = new Guid("a419de8f-d759-4db9-b9a7-c2cd14174987"),
            MAuthServiceUrl = new Uri("https://mauth.imedidata.com"),
            AuthenticateRequestTimeoutSeconds = 3,
            MAuthServiceRetryPolicy = MAuthServiceRetryPolicy.RetryOnce,
            HideExceptionsAndReturnUnauthorized = true,
            PrivateKey = "ServerPrivateKey.pem",

            // when ready to disable authentication of V1 protococl
            options.DisableV1 = true

            // if loggerfactory is present
            options.loggerfactory = new Microsoft.Extensions.Logging.LoggerFactory(); // or provide the existing loggerfactory
        };

        config.MessageHandlers.Add(new MAuthAuthenticatingHandler(options));
    }
}
```

Alternatively, you can add the authenticating handler to a specific route when you define the route:

```C#
using Medidata.MAuth.WebApi;

public static class WebApiConfig
{
    public static void Register(HttpConfiguration config)
    {
        var options = // See the previous example

        config.Routes.MapHttpRoute(
            name: "Route1",
            routeTemplate: "api/{controller}/{id}",
            defaults: new { id = RouteParameter.Optional },
            constraints: null,
            handler: new MAuthAuthenticatingHandler(options)
        );
    }
}
```

In the examples above, the `MAuthWebApiOptions` instance has the same properties as the OWIN- and
ASP.NET Core-specific `MAuthMiddlewareOptions`.

## Frequently Asked Questions

##### What are the license terms for Medidata.MAuth?

The framework is licensed under the [MIT licensing terms](https://github.com/mdsol/mauth-client-dotnet/blob/master/LICENSE.md).

##### What is the current target .NET Framework version?

The current target is **.NET Framework 4.6.1** - this means that you have to use at least this target framework version
in your project in order to make Medidata.MAuth work for you.

##### Is there an .NET Standard/Core support?

Yes, for signing outgoing requests you can use the library with any framework which implements
the **.NET Standard 2.0** and onwards; additionally we support the **ASP.NET Core App 2.1** and onwards with a middleware
for authenticating the incoming requests.

##### What Cryptographic provider is used for the encryption/decryption?

In the latest version of 4.0.0, we are using the available dotnet security [System.Security.Cryptography] which works 
for both **.NET Framework 4.6.1** and **.NET Standard 2.0** in case of V2 protocol. However, for the continue support 
of V1 protcol, we are still maintaining the BouncyCastle library as mentioned below.

On the .NET Framework side (WebAPI, Owin, Core) we are using the latest version (as of date 1.81) of the
[BouncyCastle](https://github.com/bcgit/bc-csharp) library; on the .NET Standard side (Core, AspNetCore) we are using
the portable fork of the [BouncyCastle](https://github.com/onovotny/BouncyCastle-PCL) library.

##### What are the major changes in the 5.0.0 version?
In this version we have removed the property `DisableV1` from `MAuthSigningOptions`. Instead, we have added new option as 
`SignVersions` in `MAuthSigningOptions` which takes enumeration values of MAuth protcol versions `MWS` and/ or `MWSV2` protocol. 
If this option is not provided, then it will sign in by `MWS` protocol as default. 

##### What are the major changes in the 4.0.0 version?

In this version we have added support for V2 protocol which uses `MCC-Authentication` as MAuthHeader and  `MCC-Time` as
MAuthTimeHeader. And, this V2 protocol supports for signing and authenticating url with query string parameters.
For Signing, we added two new options in `MAuthSigningOptions`: `MAuthVersion` which is mandatory and takes enumeration
 value of `MAuthVersion.MWSV2` for V2 protocol or `MAuthVersion.MWS` for continue of using V1 protocol.
Another option `DisableV1` is `false` by default if not provided. But, it is needed to provide as `true` when the client 
need to sign on by no more supporting V1 protocol.

Also while authentication, the logic defaults to check for V2 protcol header `MWSV2` and if fails then only fallback to 
check for V1 protocol header for `MWS`. Also, `MAuthOptionsBase` includes new option as `DisableV1` which is `false` by 
default and need to be passed as `true` if the authenticating client no longer wants to support V1 protocol.

##### What are the major changes in the 2.0.0 version?

In this version we have only one major and a minor change: from this version the `MAuthSigningHandler` is accepting an
`MAuthSigningOptions` instance instead of an `MAuthOptions` instance (which in turn set to be an abstract class).
This change was necessary because the MAuthOptions object contains the `MAuthServiceUrl` property, which is not required
for signing, but it had to be set to a valid Url nonetheless.

The other underlying change is that in the OWIN middleware the infrastructure provided request body stream gets replaced
with a `MemoryStream` in cases when the original body stream is not seekable. This change was necessary, because in
order to authenticate the request we need to read the body, but if the body stream is not seekable we are not able to
restore it for the subsequent middlewares to read. Typical example for this is when the OWIN selfhost infrastructure
is used as it wraps the original stream in a non-seekable version.

##### Does Medidata.MAuth support caching?

Yes, all the **ASP.NET WebApi** handler and the **Owin** and **ASP.NET Core** middlewares support caching of the `ApplicationInfo` from the MAuth server in
order to not overload it with client information requests (and gradually improve the response times from the middlewares).
The cache expiration will be set according to the response cache header (max-age) from the MAuth server - or if this
information not provided, it will be **1 hour** by default for successful requests (i.e. valid application uuids).

##### The documentation for the `MAuthServiceRetryPolicy.Agressive` retry policy says that it is not recommended for production use. What is the reason for this?

This policy will make the number of requests to the MAuth service to an overall 10 attempts. We believe that the chance
to receive a successful response from the MAuth service is gradually decreasing by the number of attempts (the more
the clients are sending requests to a presumably overloaded server the less the chance for a successful response) -
therefore we do not recommend to use this policy in any production scenario.
