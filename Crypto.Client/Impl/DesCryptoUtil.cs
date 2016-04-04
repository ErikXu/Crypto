using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto.Client.Impl
{
    public class DesCryptoUtil : IDesCryptoUtil
    {
        /// <summary>
        /// The key, length is 8, generated on https://www.random.org/strings/
        /// You can also use the GenerateKey method in the DESCryptoServiceProvider to generate the key.
        /// </summary>
        private static readonly byte[] Key = Encoding.ASCII.GetBytes("0e3Nl9Z9");

        /// <summary>
        /// The iv, length is 8, generated on https://www.random.org/strings/
        /// You can also use the GenerateIV method in the DESCryptoServiceProvider to generate the iv.
        /// </summary>
        private static readonly byte[] Iv = Encoding.ASCII.GetBytes("62EcX79F");

        public byte[] Encrypt(byte[] plainBytes)
        {
            using (var provider = new DESCryptoServiceProvider())
            {
                provider.Key = Key;
                provider.IV = Iv;
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, provider.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    return memoryStream.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] encryptedBytes)
        {
            using (var provider = new DESCryptoServiceProvider())
            {
                provider.Key = Key;
                provider.IV = Iv;
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, provider.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    return memoryStream.ToArray();
                }
            }
        }
    }
}