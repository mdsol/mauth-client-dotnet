# Changes in Medidata.MAuth

## v5.1.3
- **[All]** Removed target framework multitargeting and specified single target framework for all packages
- **[Core]** Specified target framework as .NET Standard 2.0
- **[AspNetCore]** Specified target framework as .NET Standard 2.0
- **[Owin]** Specified target framework as .NET Framework 4.6.1
- **[WebApi]** Specified target framework as .NET Framework 4.6.1

## v5.1.2
- **[Core]** Removed unnecessary dependency on `System.Net.Http` package.

## v5.1.1
- **[Core]** Fixed an issue with internal caching for the utility extension `Authenticate()` method.

## v5.1.0
- **[Core]** Added multi-target for .NET 5 to support synchronus HttpClient requests.
- **[Core]** Updated MAuthSigningHandler to sign synchronus requests.
- **[Core]** Updated MAuthAuthenticator to create and reuse a single HttpClient instead of creating a new one for each MAuthRequestRetrier.
- **[Core]** Updated MAuthAuthenticator to limit the calls to the cache item factory method to a single thread per key not already in the cache.

## v5.0.1
- **[Core]** Inflate private key upon set in options classes.

## v5.0.0
 - **[Core]** Added normalization of Uri AbsolutePath.
 - **[Core]** Added unescape step in query_string encoding to remove `double encoding`.
 - **[Core]** Replace `DisableV1`option with `SignVersions` option and change the default signing to `MAuthVersion.MWS` only.
 - **[Core]** Added parsing code to test with mauth-protocol-test-suite.
 - **[Core]** Fixed bug in sorting of query parameters.

## v4.0.2
- **[AspNetCore]** Update aspnetcore version to aspnetcore2.1 LTS.
- **[Core]** Fallback to V1 protocol when V2 athentication fails.

## v4.0.1
- **[Core]** Fixed default sigining with both MWS and MWSV2 instead of option selected by consuming application.
- **[Core]** Fixed an issue related to token request path which is same for both MWS and MWSV2 protocol.
- **[Core]** Fixed a bug related to signing with MWSV2 protocol which was due to error in signature.

## v4.0.0
- **[All]** Added implementation for MWSV2 signinig and authentication. Added logging support during MAuthentication.

## v3.1.3
- **[Core]** Refactored `MAuthCoreExtensions.cs` and moved Signing and Verification method into `IMAuthCore.cs`.

## v3.1.2
- **[Core]** Fixed and enabled caching of the `ApplicationInfo` from the MAuth server.

## v3.1.1
- **[Core]** Added `ConfigureAwait(false)` avoiding any possible deadlocks.

## v3.1.0
- **[Core]** Added a new extension method to the utilities which will authenticate a `HttpRequestMessage` with the
provided options.

## v3.0.4
- **[Core]** Fixed an issue with HTTP requests having binary content (the authentication was failing in this case)

## v3.0.3
- **[Core]** Fixed concurrency and memory issues with the `MAuthRequestRetrier`

## v3.0.2
- **[Core]** Exposed the `MAuthOptionsBase.MAuthServerHandler` property as public in order to be able to inject custom handlers for the MAuth server communication.

## v3.0.1
- **[Core]** Removed constraint for the application uuids to be only version 4. Now the MAuth header validation won't throw error if the provided uuid is not version 4.

## v3.0.0
- **[All]** **Breaking** - Changed the HTTP status code response in case of any errors (including authentication and validation errors) from Forbidden (403) to Unauthorized (401).
`HideExceptionsAndReturnForbidden` property of MAuth option class has also been renamed to `HideExceptionsAndReturnUnauthorized`.

## v2.4.1
- **[AspNetCore]** **[Owin]** Fixed an issue with the request body being not rewound in the middlewares before passing
down the chain

## v2.4.0
- **[Core]** Added a utility extension class to help using MAuth specific processing methods

## v2.3.0
- **[AspNetCore]** Added a new middleware to be able to use MAuth with the ASP.NET Core MVC
infrastructure
- **[All]** The private key property value on the options objects now can
be a file path reference to a file containing the key - the library will automatically read the key from the file if it
detects that the value is a file path instead of the key itself
- **[All]**  The private key now line ending agnostics - the library
will use the key with (Windows- or Unix-style) or without line endings, or with varying number of characters in a row
(this is very useful if you want to serve the private key from an environment variable for example)

## v2.2.0
- **[Core]** Decreased the **default** timeout from 10 seconds to 3 seconds for the MAuth service
requests in order to decrease the chance of service request congestion (the timeout still configurable in the options)
- **[Core]** Added a new feature to make multiple attempts to communicate with the MAuth service in case
there are unsuccessful responses. The number of attempts (i.e. retry policy) is configurable through the options
(`MAuthServiceRetryPolicy`)
- **[Core]** Fixed the .NET Framework assemblies being referenced as dependencies instead of
framework assemblies causing unnecessary package downloads and referencing from NuGet
- **[All]** Updated copyright year numbers to the current (2017) year
- **[All]** Added cache-specific information to the README FAQ section

## v2.1.1
- **[Core]** Fixed the NetStandard.Library being a common dependency causing unnecessary package
downloads and referencing from NuGet

## v2.1.0
- Added support for .NET Core with netstandard1.4

## v2.0.0
- **[Core]** The `MAuthSigningHandler` is accepting an `MAuthSigningOptions` instance instead of
an `MAuthOptions` instance (which in turn set to be an abstract class)
- [**Owin]** The OWIN middleware infrastructure provided request body stream gets replaced
with a `MemoryStream` in cases when the original body stream is not seekable.

## v1.0.0
- Initial version
