# Changes in Medidata.MAuth

## v2.1.0
- Added support for .NET Core with netstandard1.6.1

## v2.0.0
- **[Medidata.MAuth.Core]** The `MAuthSigningHandler` is accepting an `MAuthSigningOptions` instance instead of
an `MAuthOptions` instance (which in turn set to be an abstract class)
- [**Medidata.MAuth.Owin]** The OWIN middleware infrastructure provided request body stream gets replaced 
with a `MemoryStream` in cases when the original body stream is not seekable.

## v1.0.0
- Initial version