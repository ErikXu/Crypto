using System;
using System.Linq;
using Crypto.Client;
using Crypto.Client.Impl;
using NUnit.Framework;

namespace Crypto.Entry
{
    [TestFixture]
    public class DesCryptoUtilTests
    {
        private IDesCryptoUtil _desCryptoUtil;
        private ISaltUtil _saltUtil;
        private IBytesUtil _bytesUtil;

        [SetUp]
        public void SetUp()
        {
            _desCryptoUtil = new DesCryptoUtil();
            _saltUtil = new SaltUtil();
            _bytesUtil = new BytesUtil();
        }

        [TestCase("123456")]
        [TestCase("abcdef")]
        public void Encrypt(string plainText)
        {
            var plainBytes = _bytesUtil.FromString(plainText);
            var encryptedBytes = _desCryptoUtil.Encrypt(plainBytes);
            var encryptedText = _bytesUtil.ToBase64(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("ecIwYJUsLa0=")]
        [TestCase("iPsXCjS+O0c=")]
        public void Decrypt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytes = _desCryptoUtil.Decrypt(encryptedBytes);
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
            var encryptedBytes = _desCryptoUtil.Encrypt(plainBytesWithSalts);
            var encryptedText = _bytesUtil.ToBase64(encryptedBytes);

            Console.WriteLine("Plain text:{0}, encrypted text:{1}", plainText, encryptedText);
        }

        [TestCase("Ez7cSCJMCn2fMvU9kzqxAA==")]
        [TestCase("3mYgmHUYscKDKCrwzpZ+Dw==")]
        public void DecryptWithSalt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytesWithSalts = _desCryptoUtil.Decrypt(encryptedBytes);
            var plainBytes = plainBytesWithSalts.Skip(SaltSetting.HeadSize).Take(plainBytesWithSalts.Length - SaltSetting.HeadSize - SaltSetting.TailSize).ToArray();
            var plainText = _bytesUtil.ToString(plainBytes);

            Console.WriteLine("Encrypted text:{0}, plain text:{1}", encryptedText, plainText);
        }
    }
}