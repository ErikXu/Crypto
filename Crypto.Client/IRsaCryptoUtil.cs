namespace Crypto.Client
{
    public interface IRsaCryptoUtil
    {
        RsaKey GenerateKeys();

        byte[] Sign(byte[] bytes, string privateKey);

        bool Verify(byte[] bytes, byte[] signature, string publicKey);

        byte[] Encrypt(byte[] plainBytes, string publicKey);

        byte[] Decrypt(byte[] encryptedBytes, string privateKey);
    }
}