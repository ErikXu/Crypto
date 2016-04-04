using System.Security.Cryptography;

namespace Crypto.Client.Impl
{
    public class Md5CryptoUtil : IMd5CryptoUtil
    {
        public byte[] Encrypt(byte[] plainBytes)
        {
            using (var md5 = MD5.Create())
            {
                var encryptedBytes = md5.ComputeHash(plainBytes);
                return encryptedBytes;
            }
        }
    }
}