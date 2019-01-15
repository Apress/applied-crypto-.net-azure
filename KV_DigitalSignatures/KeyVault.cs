/*
MIT License

Copyright (c) 2018 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AppliedCryptograpy.AzureKeyVault.DigitalSignatures
{
    public class KeyVault : KeyVaultBase, IKeyVault
    {
        public KeyVault()
        {
            var clientId = "insert client id";
            var clientSecret = "insert client secret";
            VaultAddress = "insert key vault address";

            ClientCredential = new ClientCredential(clientId, clientSecret);
            KeyVaultClient = new KeyVaultClient(GetAccessTokenAsync, new HttpClient());
        }


		public KeyVault(string clientId, string clientSecret, string vaultAddress )
		{
			VaultAddress = vaultAddress;

			ClientCredential = new ClientCredential(clientId, clientSecret);
			KeyVaultClient = new KeyVaultClient(GetAccessTokenAsync, new HttpClient());
		}

        public async Task<string> CreateKeyAsync(string keyName)
        {
            var keyBundle = GetKeyBundle();
            var createdKey = await KeyVaultClient.CreateKeyAsync(VaultAddress, keyName, keyBundle.Key.Kty, keyAttributes: keyBundle.Attributes, tags: GetKeyTags());

            return createdKey.KeyIdentifier.Identifier;
        }

        public async Task DeleteKeyAsync(string keyName)
        {
            await KeyVaultClient.DeleteKeyAsync(VaultAddress, keyName);
        }

        public async Task<byte[]> EncryptAsync(string keyId, byte[] dataToEncrypt)
        {
            var operationResult = await KeyVaultClient.EncryptAsync(keyId, JsonWebKeyEncryptionAlgorithm.RSAOAEP, dataToEncrypt);

            return operationResult.Result;
        }

        public async Task<byte[]> DecryptAsync(string keyId, byte[] dataToDecrypt)
        {
            var operationResult = await KeyVaultClient.DecryptAsync(keyId, JsonWebKeyEncryptionAlgorithm.RSAOAEP, dataToDecrypt);

            return operationResult.Result;
        }

        public async Task<string> SetSecretAsync(string secretName, string secretValue)
        {     
            var bundle = await KeyVaultClient.SetSecretAsync(VaultAddress, secretName, secretValue, null, "plaintext");
            return bundle.Id;
        }

		public async Task<string> GetSecretAsync(string secretName)
		{
            try
            {
                var bundle = await KeyVaultClient.GetSecretAsync(VaultAddress, secretName);
                return bundle.Value;
            }
            catch (KeyVaultErrorException)
            {
                return string.Empty;
            }
		}

        public async Task<byte[]> Sign(string keyId, byte[] hash)
        {
            var bundle = await KeyVaultClient.SignAsync(keyId, "RS256", hash);
            return bundle.Result;
        }

        public async Task<bool> Verify(string keyId, byte[] hash, byte[] signature)
        {
            var result = await KeyVaultClient.VerifyAsync(keyId, "RS256", hash, signature);
            return result;
        }
    }
}
