using System;
using Crypto.Client;
using Crypto.Client.Impl;
using NUnit.Framework;

namespace Crypto.Entry
{
    [TestFixture]
    public class RsaPkcs8CryptoUtilTests
    {
        private IRsaCryptoUtil _rsaCryptoUtil;
        private IBytesUtil _bytesUtil;

        private RsaKey _key;

        [TestFixtureSetUp]
        public void SetUp()
        {
            _rsaCryptoUtil = new RsaPkcs8CryptoUtil();
            _bytesUtil = new BytesUtil();

            //_key = _rsaCryptoUtil.GenerateKeys();
            _key = new RsaKey
            {
                Private = @"-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAPFSWsy4T/cW5aXD
aAHHIEPpD5VBYQL/VgSyBTh0WUIg4SnXI8IIP8HozkijxMcagt5gXdfb2wa0KxO6
yy6Yyzt1GfzAG2ijN0gB72s8tXgmbTCw7eAHEr+SsLMdHWPPXzQgixIQrmiPwEqi
/ACwelWSjHbu8vYC63dCdIpuPBUDAgMBAAECgYBEmYqiQ4rHzMR/eKrqRnbPl0MM
xMcVGQyUzR5azAhLmhkn0baig8HMF6f8UkGv78Nf/7jtkdwTbcgJFcKIfnrW4Lyw
FF9hwGVf2bKyRqkMiZI+e307cYevKK7KU0qCw1Z4a8KCfCt0wiCcYu/Y4Epi/q2R
xy0akcGb+bBnz6B1IQJBAP3sv/3cE3EAoPKG+cmyHv+gRDxmyhjaCWvwR7CYp0jI
EWigH0G15UzcxxSOiyPk2vjX0OUa85FmABZka6YtVVsCQQDzSzywcjOIdzuy1tdH
7gFdH2zwln2VkyWrqHDkTbApIfsV3ipsgGa2bx5DCirSe29tiI9wAwXzC08qyyVZ
b8d5AkEAlObjQxtt7yMePno2OjeQg/hYa08fjek2AyzY7U7nMf/YbZEQIzlmKGeC
+qQIJdlLKwdrgR4H3KiCvp7OnZkR5wJBANoljP48994V4w6BOrkBPHHOOrUiiupx
7SYUu1zKF/lZwbQi53EwVGiiC8VauXjPOuNAvjRWUaBSdKLPUeb2pikCQQC9xErQ
DFWwCsAUf6kTPxw6Uvn5nCx3u5J3Wdx7Urfw5c3A7BBQdsu8UP6zbyhpxJCzAbAD
hhsyI5hID8mQOUY2
-----END PRIVATE KEY-----
",
                Public = @"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxUlrMuE/3FuWlw2gBxyBD6Q+V
QWEC/1YEsgU4dFlCIOEp1yPCCD/B6M5Io8THGoLeYF3X29sGtCsTussumMs7dRn8
wBtoozdIAe9rPLV4Jm0wsO3gBxK/krCzHR1jz180IIsSEK5oj8BKovwAsHpVkox2
7vL2Aut3QnSKbjwVAwIDAQAB
-----END PUBLIC KEY-----
"
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

        [TestCase("123456", "Pj4Z4P1ktNM+MLoqO3WUBZogZjVcjz5cvMVBJ741d2wq1X8UuI2AclZueltRahGHURiJ8djTYCSEGG1oHSc1K0ilk4lz40HFu1mqv65bwglqKrX2ks1wnwnBHusbfiu4HYXNy5HN/fcjB1ah8MxZSofxaGth1xAygY9bKkIBFS0=")]
        [TestCase("abcdef", "UUOTnyWRU/b4CvALxw4VHusKBXjv32RTjuTVyZHeBaQKvlqVuMCwrdey0Z9wrh20GRspA2Je3uUfbFSxYStDnzVsXJLB3wtNvWX+NcE+h1g1LXijnediJKn6uh4UorCpVru0tZX3XrMJPeY5u8+ZBFMUP8zw078t7w1c60XpioQ=")]
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

        [TestCase("Ku82IhLYSuthVU1uN5NvUAFImWLwqaHmSuWA8dlTBLjYcJdGJmfY/BMK4JULBUauFDIyYHkFZ2j2oK+lQDw2UuXWbojLrnPZAvAbW+HB/5nuCS1mElVJr7YTq3tHb2mjcwAKx2qSnWgDO9V8akCnMMNVGLg9IN5gnjctlgu44iU=")]
        [TestCase("hBWYekZUiEiPgQTgVtVB+Ax1UOa6tKkVk4UMU2CjwFpYoOndtJu/Frs/woRdvfJBZbD/lmMOpGoK35mlX9Y0RKrZdLRM0RG8/maiQQFWCM3ELgBWqYkdVLc4RQULxfWaVFuQolXWwVk+gCUaWeCaaMEBZ28dXiUP7npaWexEcB8=")]
        public void Decrypt(string encryptedText)
        {
            var encryptedBytes = _bytesUtil.FromBase64(encryptedText);
            var plainBytes = _rsaCryptoUtil.Decrypt(encryptedBytes, _key.Private);
            var plainText = _bytesUtil.ToString(plainBytes);

            Console.WriteLine("Encrypted text:{0}, plain text:{1}", encryptedText, plainText);
        }
    }
}