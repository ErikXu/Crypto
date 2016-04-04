using System.Security.Cryptography;

namespace Crypto.Client.Impl
{
    public class RsaCryptoUtil : IRsaCryptoUtil
    {
        public RsaKey GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var key = new RsaKey
                {
                    Private = rsa.ToXmlString(true),
                    Public = rsa.ToXmlString(false)
                };

                return key;
            }
        }

        public byte[] Sign(byte[] bytes, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                var signature = rsa.SignData(bytes, new MD5CryptoServiceProvider());
                return signature;
            }
        }

        public bool Verify(byte[] bytes, byte[] signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);
                return rsa.VerifyData(bytes, new MD5CryptoServiceProvider(), signature);
            }
        }

        public byte[] Encrypt(byte[] plainBytes, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);
                var encryptedBytes = rsa.Encrypt(plainBytes, false);
                return encryptedBytes;
            }
        }

        public byte[] Decrypt(byte[] encryptedBytes, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                var decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                return decryptedBytes;
            }
        }
    }
}