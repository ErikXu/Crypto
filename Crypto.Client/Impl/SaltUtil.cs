using System.Security.Cryptography;

namespace Crypto.Client.Impl
{
    public class SaltUtil : ISaltUtil
    {
        public byte[] GenerateSalt(int size)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[size];
                rng.GetBytes(salt);
                return salt;
            }
        }
    }
}