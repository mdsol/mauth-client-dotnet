﻿using System;
using System.Text;
using System.Text.RegularExpressions;

namespace Medidata.MAuth.Core
{
    internal static class Constants
    {
        public static readonly DateTimeOffset UnixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero);
         
        public static readonly Regex AuthenticationHeaderRegex = new Regex(
            "^MWS " +
            "(?<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})" +
            ":" +
            "(?<payload>" +
                "(?:[0-9a-zA-Z+/]{4})*" +
                "(?:[0-9a-zA-Z+/]{2}==|[0-9a-zA-Z+/]{3}=)" +
                "?" +
            ")$", RegexOptions.Compiled
        );

        public static readonly string MAuthHeaderKey = "X-MWS-Authentication";

        public static readonly string MAuthTimeHeaderKey = "X-MWS-Time";

        public static readonly string KeyNormalizeLinesStartRegexPattern = "^(?<begin>-----BEGIN [A-Z ]+[-]+)";

        public static readonly string KeyNormalizeLinesEndRegexPattern = "(?<end>-----END [A-Z ]+[-]+)$";

        public static readonly byte[] NewLine = Encoding.UTF8.GetBytes("\n");

        public static readonly Regex AuthenticationHeaderRegexV2 = new Regex(
            "^MWSV2 " +
            "(?<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})" +
            ":" +
            "(?<payload>" +
            "(?:[0-9a-zA-Z+/]{4})*" +
            "(?:[0-9a-zA-Z+/]{2}==|[0-9a-zA-Z+/]{3}=)" +
            "?" +
            ");$", RegexOptions.Compiled
        );

        public static readonly string MAuthHeaderKeyV2 = "MCC-Authentication";

        public static readonly string MAuthTimeHeaderKeyV2 = "MCC-Time";

        public static readonly string MAuthTokenRequestPath = "/mauth/v1/security_tokens/";

        public static readonly Regex LowerCaseHexPattern = new Regex("%[a-f0-9]{2}", RegexOptions.Compiled);

        public static readonly Regex SlashPattern = new Regex("//+", RegexOptions.Compiled);
    }
}
