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
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AppliedCryptograpy.AzureKeyVault.HybridWithIntegrityAndSignature
{
    public class KeyVaultBase
    {
        protected KeyVaultClient KeyVaultClient;
        protected ClientCredential ClientCredential;
        protected string VaultAddress;

        protected string GetKeyUri(string keyName)
        {
            var retrievedKey = KeyVaultClient.GetKeyAsync(VaultAddress, keyName).GetAwaiter().GetResult();
            return retrievedKey.Key.Kid;
        }

        protected KeyBundle GetKeyBundle()
        {
            var defaultKeyBundle = new KeyBundle
            {
                Key = new JsonWebKey
                {
                    Kty = JsonWebKeyType.Rsa
                },
                Attributes = new KeyAttributes
                {
                    Enabled = true,
                    Expires = DateTime.Now.AddYears(1)
                }
            };

            return defaultKeyBundle;
        }

        protected Dictionary<string, string> GetKeyTags()
        {
            return new Dictionary<string, string> { { "purpose", "Master Key" }, { "LadderPay Core", "LadderPay" } };
        }

        protected Dictionary<string, string> GetSecretTags()
        {
            return new Dictionary<string, string> { { "purpose", "Encrypted Secret" }, { "LadderPay Core", "LadderPay" } };
        }

        protected async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, ClientCredential);
            Console.WriteLine(scope);
            return result.AccessToken;
        }
    }
}
