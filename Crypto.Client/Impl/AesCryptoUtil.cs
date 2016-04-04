using System.Security.Cryptography;
using System.Text;

namespace Crypto.Client.Impl
{
    public class AesCryptoUtil : IAesCryptoUtil
    {
        /// <summary>
        /// A system key and the length should be 16.
        /// You can use tool to generate the string on https://www.random.org/strings/ or other website.
        /// </summary>
        private const string SystemKeyPart = "84ImUeBn432oPkqo";

        /// <summary>
        /// A custom key and the lenth should between 4 and 16. You can use the project name as the custom key.
        /// </summary>
        private const string UserKeyPart = "AecCrypto";

        /// <summary>
        /// The combine key.
        /// </summary>
        private static readonly byte[] Key = Encoding.ASCII.GetBytes(UserKeyPart.PadRight(16, '#') + SystemKeyPart);

        /// <summary>
        /// Please indicate a random string here, and the length must be 16.
        /// You can use tool to generate the string on https://www.random.org/strings/ or other website.
        /// </summary>
        private static readonly byte[] Iv = Encoding.ASCII.GetBytes("bCNtStALc7bRqREq");

        public byte[] Encrypt(byte[] plainBytes)
        {
            return Encrypt(plainBytes, CipherMode.CBC, PaddingMode.PKCS7);
        }

        public byte[] Decrypt(byte[] encryptedBytes)
        {
            return Decrypt(encryptedBytes, CipherMode.CBC, PaddingMode.PKCS7);
        }

        private static byte[] Encrypt(byte[] plainBytes, CipherMode cipher, PaddingMode padding)
        {
            using (var aes = Rijndael.Create())
            {
                aes.Mode = cipher;
                aes.Padding = padding;

                using (var transform = aes.CreateEncryptor(Key, Iv))
                {
                    var encryptedBytes = transform.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return encryptedBytes;
                }
            }
        }

        private static byte[] Decrypt(byte[] encryptedBytes, CipherMode cipher, PaddingMode padding)
        {
            using (var aes = Rijndael.Create())
            {
                aes.Mode = cipher;
                aes.Padding = padding;

                using (var transform = aes.CreateDecryptor(Key, Iv))
                {
                    var plainBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return plainBytes;
                }
            }
        }
    }
}