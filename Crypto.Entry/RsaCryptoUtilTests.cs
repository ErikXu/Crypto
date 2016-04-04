using System;
using Crypto.Client;
using Crypto.Client.Impl;
using NUnit.Framework;

namespace Crypto.Entry
{
    [TestFixture]
    public class RsaCryptoUtilTests
    {
        private IRsaCryptoUtil _rsaCryptoUtil;
        private IBytesUtil _bytesUtil;

        private RsaKey _key;

        [TestFixtureSetUp]
        public void SetUp()
        {
            _rsaCryptoUtil = new RsaCryptoUtil();
            _bytesUtil = new BytesUtil();

            //_key = _rsaCryptoUtil.GenerateKeys();
            _key = new RsaKey
            {
                Private = "<RSAKeyValue><Modulus>uHJEx1sd+DIQ3axJpmLBktZtARDSD5kE0qP8q27zEYVS6tHI+6HVTJ8h4vtjdri2AStGZSgqChOl3K/p+EaF7oeS/krY7yNLPTEPqLAyLOb/KG4MX4abxVvKexgYUQtpL2LFDJabkmzv479dqJxetcUgm38J7DVtzs0yroQ/WMU=</Modulus><Exponent>AQAB</Exponent><P>5w2dxfWTvOHuAF7aC7IeFDdD32xzakocltcoysWufAoK47WhTElBZJZVomu3HToFDhQyj/EPxq/IqTe9Bf8ayQ==</P><Q>zFxswhNH6BloEtBRpWsiMGokWmT/y5TS/e1WOfKtmaqA8hetjbgRMT19bvrE+A97+ySi4U2fc8Kg5+7XgObQHQ==</Q><DP>f17iOt7GMrnZmhqv2QK30i0lHWWLumxglkbGFgIjzf07Q4w8/vDjO7AkRQVcTKBPaRN5TCB3se/1jlNLwKKBAQ==</DP><DQ>qcbHG9zEylABJFAo5FJCzxH/LZHm6Iy1VPvNvMqd6qG6CmYdazVWIyBAiuiOpr7Gc3iWULMaGyPAZa8JHi+jCQ==</DQ><InverseQ>j6H7KElCrIvxpisQf+Fc5wRRim6MM5kOh40sw0sSqVwFb3zlso96sxEzH1cLWJsfTitbhJWb1pBT9IDSMQeJhg==</InverseQ><D>BtbF0haAz/kbQvzmZjL3NniY5hc3krh7w0utTLX6cUXeQzKwHxRrEkI8QWxMzdQfe3+dRpbsqB7+YWZsaHZE9PkQ46jviil+0PT8o+XZYsTKcRv+q1B7D/onMKePQUfzALVzYieiGIfjVIL+zTndAW2ONHvCc2pi8+f8EuKf9EE=</D></RSAKeyValue>",
                Public = "<RSAKeyValue><Modulus>uHJEx1sd+DIQ3axJpmLBktZtARDSD5kE0qP8q27zEYVS6tHI+6HVTJ8h4vtjdri2AStGZSgqChOl3K/p+EaF7oeS/krY7yNLPTEPqLAyLOb/KG4MX4abxVvKexgYUQtpL2LFDJabkmzv479dqJxetcUgm38J7DVtzs0yroQ/WMU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
            };
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void Sign(string text)
        {
            var bytes = _bytesUtil.FromString(text);
            var signatureBytes = _rsaCryptoUtil.Sign(bytes, _key.Private);
            var signature = _bytesUtil.ToBase64(signatureBytes);

            Console.WriteLine("Text:{0}, signature:{1}", text, signature);
        }

        [TestCase("123456", "T5BS2WHA2ZvDexuEIPRSbnB7SlC1blNPi4BGcwiGovE54bmAiLIqf6p9dmsMMS+wgyKX2JPKkiNKtzts+q1yVmosqqjcmrNZbP+YF9YNqbO4Da0CJRjH1rwCa+XC7cJFKIDn85KQqtLpdr7yong0SjtXA+cDMD3dP9RoZLb+k/k=")]
        [TestCase("abcdef", "Gxf9LGx2AFmW114ex7nemDXIiEXkYmBA4bR0SMWp4M/uule171rtPIyZlX17CeNM2kmNKtxYAqsJj0Pfxb1znydtNLo/lFNkZDZkxAMx7uTLdw9Os4g5ZKXKkBbYi3aYBNY0bbICfetGRNGaGU4p8HlKm+KrijbURBKH6wE1DyI=")]
        public void Verify(string text, string signature)
        {
            var bytes = _bytesUtil.FromString(text);
            var signatureBytes = _bytesUtil.FromBase64(signature);
            var isVerified = _rsaCryptoUtil.Verify(bytes, signatureBytes, _key.Public);

            Console.WriteLine("Text:{0}, signature:{1}, is verified:{2}", text, signature, isVerified);
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void Encrypt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var encryptedBytes = _rsaCryptoUtil.Encrypt(plainBytes, _key.Public);
            var encryptedText = _bytesUtil.ToBase64(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("ZfT/2r0VqY6LX8eL+rfgufT/q+kMZsvRcDK6NafoHb+zvBN5KNxI5MAIG07Oqe3EiRH3yXrjKnePUiVvPJGW40xHm6S2yRBar61ZB3DONavwjlKQBBPGJNuW1S8aevdxFIGHazFjzv7FMCcJaAFrnNlZlkdsk67z0FbubPylPbY=")]
        [TestCase("m8rS9i1DGE6MqW0L6vcS+lthiBzFTWrfK4XS97TDyC8t0xecNsLteIGEDgrzUMVf9j0ue0HpGHslYiOUAiX1wnFcVM0aX3SAZ1NmsIFEoYhz3av3lPj/tX9Ccirn7YhQw/N5BHwxPYT3ZcRfy+ozVXBo0EFDNGoJMcysfA0u5Uk=")]
        public void Decrypt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytes = _rsaCryptoUtil.Decrypt(encryptedBytes, _key.Private);
            var plainText = _bytesUtil.ToString(plainBytes);

            Console.WriteLine("Encrypted text:{0}, plain text:{1}", encryptedText, plainText);
        }
    }
}