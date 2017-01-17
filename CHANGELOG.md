# Changes in Medidata.MAuth

## v2.1.2
- **[Medidata.MAuth.Core]** Fixed the .NET Framework assemblies being referenced as dependencies instead of
framework assemblies causing unnecessary package downloads and referencing from NuGet
- **[All]** Updated copyright year numbers to the current (2017) year
- **[All]** Added cache-specific information to the README FAQ section

## v2.1.1
- **[Medidata.MAuth.Core]** Fixed the NetStandard.Library being a common dependency causing unnecessary package
downloads and referencing from NuGet

## v2.1.0
- Added support for .NET Core with netstandard1.4

## v2.0.0
- **[Medidata.MAuth.Core]** The `MAuthSigningHandler` is accepting an `MAuthSigningOptions` instance instead of
an `MAuthOptions` instance (which in turn set to be an abstract class)
- [**Medidata.MAuth.Owin]** The OWIN middleware infrastructure provided request body stream gets replaced 
with a `MemoryStream` in cases when the original body stream is not seekable.

## v1.0.0
- Initial version