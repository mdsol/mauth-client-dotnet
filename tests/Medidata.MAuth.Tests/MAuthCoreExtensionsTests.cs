using Medidata.MAuth.Core;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthCoreExtensionsTests
    {
        [Fact]
        public static void BuildEncodedQueryParams_WillEncodeQueryStringWithSpecialCharacters()
        {
            var queryString = "key=-_.~!@#$%^*()+{}|:\"'`<>?";
            var expected = "key=-_.~%21%40%23%24%25%5E%2A%28%29%2B%7B%7D%7C%3A%22%27%60%3C%3E%3F";
            Assert.Equal(queryString.BuildEncodedQueryParams(), expected);
        }

        [Fact]
        public static void BuildEncodedQueryParams_WillEncodeQueryStringBySortingWithCodePointAscending()
        {
            var queryString = "∞=v&キ=v&0=v&a=v";
            var expected = "0=v&a=v&%E2%88%9E=v&%E3%82%AD=v";
            Assert.Equal(queryString.BuildEncodedQueryParams(), expected);
        }

        [Fact]
        public static void BuildEncodedQueryParams_WillEncodeQueryStringBySortingWithValuesIfSameKeys()
        {
            var queryString = "a=b&a=c&a=a";
            var expected = "a=a&a=b&a=c";
            Assert.Equal(queryString.BuildEncodedQueryParams(), expected);
        }

        [Fact]
        public static void BuildEncodedQueryParams_WillHandlesQueryStringWithEmptyValues()
        {
            var queryString = "k=&k=v";
            Assert.Equal(queryString.BuildEncodedQueryParams(), queryString);
        }
    }
}
