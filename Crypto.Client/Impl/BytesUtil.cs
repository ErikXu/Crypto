using System;
using System.Linq;
using System.Text;

namespace Crypto.Client.Impl
{
    public class BytesUtil : IBytesUtil
    {
        public byte[] FromString(string text)
        {
            return Encoding.UTF8.GetBytes(text);
        }

        public byte[] FromBase64(string base64Text)
        {
            return Convert.FromBase64String(base64Text);
        }

        public string ToString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        public string ToBase64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        public string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder();
            foreach (var b in bytes)
            {
                builder.AppendFormat("{0:X2}", b);
            }
            return builder.ToString();
        }

        public byte[] Combine(params byte[][] arrays)
        {
            var result = new byte[arrays.Sum(a => a.Length)];

            var offset = 0;

            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }
    }
}