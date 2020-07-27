using Medidata.MAuth.Core;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class ProtocolTestSuiteHelper
    {
        private string _testSuitePath;
        private string _testCasePath;

        public ProtocolTestSuiteHelper()
        {
            var currentDirectory = Environment.CurrentDirectory;
            _testSuitePath = Environment.GetEnvironmentVariable("TEST_SUITE_PATH") != null
                ? Environment.GetEnvironmentVariable("TEST_SUITE_PATH")
                : Path.GetFullPath(Path.Combine(currentDirectory, @"..\..\..\..\..\..\mauth-protocol-test-suite"));
            _testCasePath = $"{_testSuitePath}/protocols/MWSV2";
        }

        public async Task<SigningConfig> LoadSigningConfig()
        {
            var configFile = $"{_testSuitePath}/signing-config.json";

            var signingConfig = await ReadSigningConfigParameters(configFile);
            if (signingConfig is null )return null;

            signingConfig.PrivateKey = await GetPrivateKey();
            return signingConfig;
        }

        public async Task<Guid> ReadSignInAppUuid()
        {
            var signConfig = await LoadSigningConfig();
            return signConfig != null ? signConfig.AppUuid : default;
        }

        public async Task<string> GetPrivateKey()
        {
            var filePath = $"{_testSuitePath}/signing-params/rsa-key";
            return await ReadValueFromPath(filePath);
        }

        public async Task<string> GetPublicKey()
        {
            var publicKeyFilePath = $"{_testSuitePath}/signing-params/rsa-key-pub";
            return await ReadValueFromPath(publicKeyFilePath);
        }

        public async Task<UnSignedRequest> LoadUnsignedRequest(string testCaseName)
        {
            var reqFilePath = $"{_testCasePath}/{testCaseName}/{testCaseName}.req";
            var unsignedRequest = await ReadRequestParameters(reqFilePath);
            unsignedRequest.Body = !string.IsNullOrEmpty(unsignedRequest.Body) 
                ? Convert.ToBase64String(unsignedRequest.Body.ToBytes()) : unsignedRequest.Body;

            if (!string.IsNullOrEmpty(unsignedRequest.BodyFilePath))
            {
                unsignedRequest.Body = GetTestRequestBody(testCaseName, unsignedRequest.BodyFilePath);
            }
            return unsignedRequest;
        }

        public string GetTestRequestBody(string caseName, string bodyFilepath)
        {
            if (string.IsNullOrEmpty(bodyFilepath))
                return null;
            var completebodyFilePath = $"{_testCasePath}/{caseName}/{bodyFilepath}";
            var bytes = File.ReadAllBytes(completebodyFilePath);
            return Convert.ToBase64String(bytes);
        }

        public string[] GetTestCases()
        {
            return Directory.Exists(_testCasePath)
                ? Directory.GetDirectories(_testCasePath).Select(x => Path.GetFileName(x)).ToArray()
                : null;
        }

        public async Task<string> ReadStringToSign(string testCaseName)
        {
            var stsFilePath = $"{_testCasePath}/{testCaseName}/{testCaseName}.sts";
            var sts = await ReadValueFromPath(stsFilePath);
            return sts.Replace("\r", "");
        }

        public async Task<string> ReadDigitalSignature(string testCaseName)
        {
            var sigFilePath = $"{_testCasePath}/{testCaseName}/{testCaseName}.sig";
            return await ReadValueFromPath(sigFilePath);
        }

        public async Task<AuthenticationHeader> ReadAuthenticationHeader(string testCaseName)
        {
            var authzFilePath = $"{_testCasePath}/{testCaseName}/{testCaseName}.authz";
            return JsonConvert.DeserializeObject<AuthenticationHeader>(
                await ReadValueFromPath(authzFilePath));
        }

        private async Task<UnSignedRequest> ReadRequestParameters(string requestPath) =>
            JsonConvert.DeserializeObject<UnSignedRequest>(
                await ReadValueFromPath(requestPath));

        private async Task<SigningConfig> ReadSigningConfigParameters(string signingConfigJson)
        {
            var signingConfig = await ReadValueFromPath(signingConfigJson);
            return signingConfig != null ? JsonConvert.DeserializeObject<SigningConfig>(signingConfig) : null;
        }
           

        private async Task<string> ReadValueFromPath(string filePath)
        {
            try
            {
                using (StreamReader sr = File.OpenText(filePath))
                {
                    return await sr.ReadToEndAsync();
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }

}
