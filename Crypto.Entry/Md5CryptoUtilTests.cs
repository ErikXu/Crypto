using System;
using Crypto.Client;
using Crypto.Client.Impl;
using NUnit.Framework;

namespace Crypto.Entry
{
    [TestFixture]
    public class Md5CryptoUtilTests
    {
        private IMd5CryptoUtil _md5CryptoUtil;
        private ISaltUtil _saltUtil;
        private IBytesUtil _bytesUtil;

        [SetUp]
        public void SetUp()
        {
            _md5CryptoUtil = new Md5CryptoUtil();
            _saltUtil = new SaltUtil();
            _bytesUtil = new BytesUtil();
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void Encrypt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var encryptedBytes = _md5CryptoUtil.Encrypt(plainBytes);
            var encryptedText = _bytesUtil.ToHex(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void EncryptWithSalt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var headSalt = _saltUtil.GenerateSalt(SaltSetting.HeadSize);
            var tailSalt = _saltUtil.GenerateSalt(SaltSetting.TailSize);
            var plainBytesWithSalts = _bytesUtil.Combine(headSalt, plainBytes, tailSalt);
            var encryptedBytes = _md5CryptoUtil.Encrypt(plainBytesWithSalts);
            var encryptedText = _bytesUtil.ToHex(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }
    }
}