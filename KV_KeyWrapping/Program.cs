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
using System.Text;
using System.Threading.Tasks;

namespace AppliedCryptograpy.AzureKeyVault.KeyWrapping
{
    class Program
    {
        public static async Task Main(string[] args)
        {
            await KeyVault();
        }

        public static async Task KeyVault()
        {
            IKeyVault vault = new KeyVault();

            const string MY_KEY_NAME = "StephenHauntsKey";
            string keyId = await vault.CreateKeyAsync(MY_KEY_NAME);

            byte[] localKey = SecureRandom.GenerateRandomNumber(32);

            // Encrypt our local key with Key Vault and Store it in the database
            byte[] encryptedKey = await vault.EncryptAsync(keyId, localKey);


            // Get our encrypted key from the database and decrypt it with the Key Vault.
            byte[] decryptedKey = await vault.DecryptAsync(keyId, encryptedKey);

            // Now we have recovered the key with the Key Vault we can encrypt with AES locally.
            byte[] iv = SecureRandom.GenerateRandomNumber(16);
            byte[] encryptedData = AesEncryption.Encrypt(Encoding.ASCII.GetBytes("MEGA TOP SECRET STUFF"), decryptedKey, iv);
            byte[] decryptedMessage = AesEncryption.Decrypt(encryptedData, decryptedKey, iv);

            var encryptedText = Convert.ToBase64String(encryptedData);
            var decryptedData = Encoding.UTF8.GetString(decryptedMessage);

            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Deleted : " + keyId);
        }
    }
}
