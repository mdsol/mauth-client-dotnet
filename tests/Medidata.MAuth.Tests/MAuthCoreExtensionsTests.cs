using Medidata.MAuth.Core;
using System;
using Xunit;

namespace Medidata.MAuth.Tests
{
    public static class MAuthCoreExtensionsTests
    {
        [Fact]
        public static void BuildEncodedQueryParams_WillEncodeQueryStringWithSpecialCharacters()
        {
            var queryString = "key=-_.~!@#$%^*()+{}|:\"'`<>?";
            var expected = "key=-_.~%21%40%23%24%25%5E%2A%28%29%20%7B%7D%7C%3A%22%27%60%3C%3E%3F";
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

        [Fact]
        public static void BuildEncodedQueryParams_WithUnescapedTilda()
        {
            var queryString = "k=%7E";
            var expectedString = "k=~";
            Assert.Equal(expectedString, queryString.BuildEncodedQueryParams());
        }

        [Fact]
        public static void BuildEncodedQueryParams_SortAfterUnescaping()
        {
            var queryString = "k=%7E&k=~&k=%40&k=a";
            var expectedString = "k=%40&k=a&k=~&k=~";
            Assert.Equal(expectedString, queryString.BuildEncodedQueryParams());
        }

        [Fact]
        public static void BuildEncodedQueryParams_WithNullQueryString()
        {
            string queryString = null;
            Assert.Empty(queryString.BuildEncodedQueryParams());
        }

        [Fact]
        public static void NormalizeUriPath_WithNullPath()
        {
            string path =null;
            Assert.Empty(path.NormalizeUriPath());
        }

        [Fact]
        public static void NormalizeUriPath_WithValues()
        {
            var testcases = CreateUriPathArray();
            for(int i = 0; i <= testcases.GetUpperBound(0); i++)
            {
                var request = new Uri("http://localhost:2999" + testcases[i, 0]);
               Assert.Equal(testcases[i,1], request.AbsolutePath.NormalizeUriPath());
            }
        }

        private static string [ , ] CreateUriPathArray()
        {
            return new string [10, 2] {
                { "/example/sample", "/example/sample"},
                {"/example//sample/", "/example/sample/"},
                {"//example///sample/", "/example/sample/"},
                {"/%2a%80", "/%2A%80"},
                { "/example/", "/example/" },
                {"/example/sample/..", "/example/"},
                {"/example/sample/..", "/example/"},
                {"/example/sample/../../../..", "/"},
                {"/example//./.", "/example/"},
                {"/./example/./.", "/example/"}
            };
        }
    }
}
