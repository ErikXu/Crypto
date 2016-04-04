namespace Crypto.Client
{
    public interface IAesCryptoUtil
    {
        byte[] Encrypt(byte[] plainBytes);

        byte[] Decrypt(byte[] encryptedBytes);
    }
}