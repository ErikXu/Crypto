namespace Crypto.Client
{
    public interface IBytesUtil
    {
        byte[] FromString(string text);

        byte[] FromBase64(string base64Text);

        string ToString(byte[] bytes);

        string ToBase64(byte[] bytes);

        string ToHex(byte[] bytes);

        byte[] Combine(params byte[][] arrays);
    }
}