using Medidata.MAuth.Core;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Medidata.MAuth.Tests.ProtocolTestSuite
{
    public class ProtocolTestSuiteHelper
    {
        private string _testCasePath;
        private string _testSuiteModulePath;

        public ProtocolTestSuiteHelper()
        {
            var currentDirectory = Environment.CurrentDirectory;
            _testSuiteModulePath = Path.GetFullPath(
                Path.Combine(currentDirectory, "../../../../../mauth-protocol-test-suite"));
            _testCasePath = Path.Combine(_testSuiteModulePath, "protocols/MWSV2");
        }

        public async Task<SigningConfig> LoadSigningConfig()
        {
            var configFile = Path.Combine(_testSuiteModulePath, "signing-config.json");

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
            var filePath = Path.Combine(_testSuiteModulePath, "signing-params/rsa-key");
            return Encoding.UTF8.GetString(await ReadAsBytes(filePath));
        }

        public async Task<string> GetPublicKey()
        {
            var publicKeyFilePath = Path.Combine(_testSuiteModulePath, "signing-params/rsa-key-pub");
            return Encoding.UTF8.GetString(await ReadAsBytes(publicKeyFilePath));
        }

        public async Task<UnSignedRequest> LoadUnsignedRequest(string testCaseName)
        {
            var reqFilePath = Path.Combine(_testCasePath, testCaseName, $"{testCaseName}.req");
            var unsignedRequest = await ReadUnsignedRequest(reqFilePath);
            unsignedRequest.Body = !string.IsNullOrEmpty(unsignedRequest.BodyFilePath)
                ? await GetBinaryBody(testCaseName, unsignedRequest.BodyFilePath)
                : !string.IsNullOrEmpty(unsignedRequest.Body) 
                    ? Convert.ToBase64String(unsignedRequest.Body.ToBytes()) : unsignedRequest.Body;

            return unsignedRequest;
        }

        public async Task<string> GetBinaryBody(string caseName, string bodyFilepath)
        {
            if (string.IsNullOrEmpty(bodyFilepath))
                return null;
            var completebodyFilePath = Path.Combine(_testCasePath, caseName, bodyFilepath);
            var bytes = await ReadAsBytes(completebodyFilePath);
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
            var stsFilePath = Path.Combine(_testCasePath, testCaseName, $"{testCaseName}.sts");
            var sts = Encoding.UTF8.GetString(await ReadAsBytes(stsFilePath));
            return sts.Replace("\r", "");
        }

        public async Task<string> ReadDigitalSignature(string testCaseName)
        {
            var sigFilePath = Path.Combine(_testCasePath, testCaseName, $"{testCaseName}.sig");
            return Encoding.UTF8.GetString(await ReadAsBytes(sigFilePath));
        }

        public async Task<AuthenticationHeader> ReadAuthenticationHeader(string testCaseName)
        {
            var authzFilePath = Path.Combine(_testCasePath, testCaseName, $"{testCaseName}.authz");
            return JsonConvert.DeserializeObject<AuthenticationHeader>(
                 Encoding.UTF8.GetString(await ReadAsBytes(authzFilePath)));
        }

        private async Task<UnSignedRequest> ReadUnsignedRequest(string requestPath) =>
            JsonConvert.DeserializeObject<UnSignedRequest>(
                 Encoding.UTF8.GetString(await ReadAsBytes(requestPath)));

        private async Task<SigningConfig> ReadSigningConfigParameters(string signingConfigJson)
        {
            var signingConfigBytes = await ReadAsBytes(signingConfigJson);
            return JsonConvert.DeserializeObject<SigningConfig>(Encoding.UTF8.GetString(signingConfigBytes));
        }

        private async Task<byte[]> ReadAsBytes(string filePath)
        {
            using (FileStream stream = File.OpenRead(filePath))
            {
                byte[] result = new byte[stream.Length];
                await stream.ReadAsync(result, 0, (int)stream.Length);
                return result;
            }
        }
    }
}
