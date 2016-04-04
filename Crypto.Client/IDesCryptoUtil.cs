namespace Crypto.Client
{
    public interface IDesCryptoUtil
    {
        byte[] Encrypt(byte[] plainBytes);

        byte[] Decrypt(byte[] encryptedBytes);
    }
}