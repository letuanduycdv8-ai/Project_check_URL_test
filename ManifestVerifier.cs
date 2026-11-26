using System;
using System.Security.Cryptography;
using System.Text;

namespace Project_check_URL
{
    public static class ManifestVerifier
    {
        // Открытый ключ будет создан на следующем шаге.
        // НЕ помещайте PRIVATE KEY в Launcher.
        private const string PublicKeyXml = "<RSAKeyValue>\r\n<Modulus>9aqw/ph08Sens2rtNAY0JjAmrZV+fdIB/iVpSssooH4jZeHcisHOWmenhujHPVpiCAAEfIili4I0Dp4P7lIz2IwaLYD3uN0ewjzQzgqAcpL/pUIbovFqAhK55V29UlftT76wBmFY8zOjIUraDsktG7zMjR9lOsnKx55u+EvabNu5OSUAXzGH0nW5ZWD2xERpVuPWrCJTJ585Lq/qWEHdNw4x70C6kLNRhuqOdCuWPuhJmO0FG1D4qzgos6+4aGQvugjWLhlCbMf6gAHJCvx2mH5zLOzXpou52KFcU7Blu3WHl3NUzIa/8jpdu6pB9OrIw8Zm6wC7Sj2BBf6r4TU6zQ==</Modulus>\r\n<Exponent>AQAB</Exponent>\r\n</RSAKeyValue>";

        public static bool Verify(
            byte[] manifestBytes,
            string signatureText)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(PublicKeyXml))
                    throw new InvalidOperationException(
                        "RSA public key has not been configured.");

                byte[] signature = Convert.FromBase64String(
                    signatureText.Trim());

                using (var rsa = RSA.Create())
                {
                    rsa.FromXmlString(PublicKeyXml);

                    return rsa.VerifyData(
                        manifestBytes,
                        signature,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                }
            }
            catch
            {
                return false;
            }
        }
    }
}