using System;
using System.Linq;
using Crypto.Client;
using Crypto.Client.Impl;
using NUnit.Framework;

namespace Crypto.Entry
{
    [TestFixture]
    public class AesCryptoUtilTests
    {
        private IAesCryptoUtil _aesCryptoUtil;
        private ISaltUtil _saltUtil;
        private IBytesUtil _bytesUtil;

        [SetUp]
        public void SetUp()
        {
            _aesCryptoUtil = new AesCryptoUtil();
            _saltUtil = new SaltUtil();
            _bytesUtil = new BytesUtil();
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void Encrypt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var encryptedBytes = _aesCryptoUtil.Encrypt(plainBytes);
            var encryptedText = _bytesUtil.ToBase64(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("HDHlYOQuENPmtjFKvLZIEA==")]
        [TestCase("YO3ErLZ5/izaDgD0M0uYDg==")]
        public void Decrypt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytes = _aesCryptoUtil.Decrypt(encryptedBytes);
            var plainText = _bytesUtil.ToString(plainBytes);

            Console.WriteLine("Encrypted text:{0}, plain text:{1}", encryptedText, plainText);
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void EncryptWithSalt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var headSalt = _saltUtil.GenerateSalt(SaltSetting.HeadSize);
            var tailSalt = _saltUtil.GenerateSalt(SaltSetting.TailSize);
            var plainBytesWithSalts = _bytesUtil.Combine(headSalt, plainBytes, tailSalt);
            var encryptedBytes = _aesCryptoUtil.Encrypt(plainBytesWithSalts);
            var encryptedText = _bytesUtil.ToBase64(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("Leu9NnY9qA3/9u5uUZoXGQ==")]
        [TestCase("eqcbaEOL9mHlQh3ERnGNeA==")]
        public void DecryptWithSalt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytesWithSalts = _aesCryptoUtil.Decrypt(encryptedBytes);
            var plainBytes = plainBytesWithSalts.Skip(SaltSetting.HeadSize).Take(plainBytesWithSalts.Length - SaltSetting.HeadSize - SaltSetting.TailSize).ToArray();
            var plainText = _bytesUtil.ToString(plainBytes);

            Console.WriteLine("Encrypted text:{0}, plain text:{1}", encryptedText, plainText);
        }
    }
}