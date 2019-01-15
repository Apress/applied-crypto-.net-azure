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

namespace AppliedCryptograpy.AzureKeyVault.SimpleEncryptDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            KeyVault().GetAwaiter().GetResult();
        }

        public static async Task KeyVault()
        {
            IKeyVault vault = new KeyVault();

            const string MY_KEY_NAME = "MyKeyVaultKey";

            string keyId = await vault.CreateKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Written : " + keyId);

            // Test encryption and decryption.
            string dataToEncrypt = "Hello World!!";

            byte[] encrypted = await vault.EncryptAsync(keyId, Encoding.ASCII.GetBytes(dataToEncrypt));
            byte[] decrypted = await vault.DecryptAsync(keyId, encrypted);

            var encryptedText = Convert.ToBase64String(encrypted);
            var decryptedData = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("Encrypted Data : " + encryptedText);
            Console.WriteLine("Decrypted Data : " + decryptedData);

            // Remove HSM backed key
            await vault.DeleteKeyAsync(MY_KEY_NAME);
            Console.WriteLine("Key Deleted : " + keyId);
        }
    }
}
