using System.Security.Cryptography;

namespace Crypto.Client.Impl
{
    public class Sha1CryptoUtil : ISha1CryptoUtil
    {
        public byte[] Encrypt(byte[] plainBytes)
        {
            using (var sha1 = SHA1.Create())
            {
                var encryptedBytes = sha1.ComputeHash(plainBytes);
                return encryptedBytes;
            }
        }
    }
}