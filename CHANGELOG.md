# Changes in Medidata.MAuth

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
