namespace Crypto.Client
{
    public interface ISaltUtil
    {
        byte[] GenerateSalt(int size); 
    }
}