using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SwitchLink.Cryptography
{
    public class CryptoHelper
    {
        public static string GetMD5HashFromFile(string fileName)
        {
            var file = new FileStream(fileName, FileMode.Open);
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] retVal = md5.ComputeHash(file);
            file.Close();

            var sb = new StringBuilder();
            for (int i = 0; i < retVal.Length; i++)
            {
                sb.Append(retVal[i].ToString("x2"));
            }
            return sb.ToString();
        }

        #region do not modify this code
        /*
     * This has been copied to report server security extension 
     * for decrypting authorization code with secret key, changing this will have side effects
     */
        //create and initialize a crypto algorithm
        private static SymmetricAlgorithm getAlgorithm(string password)
        {
            SymmetricAlgorithm algorithm = Rijndael.Create();
            var rdb = new Rfc2898DeriveBytes(
                password, new byte[]
                {
                    0x53, 0x6f, 0x64, 0x69, 0x75, 0x6d, 0x20, // salty goodness
                    0x43, 0x68, 0x6c, 0x6f, 0x72, 0x69, 0x64, 0x65
                }
                );
            algorithm.Padding = PaddingMode.ISO10126;
            algorithm.Key = rdb.GetBytes(32);
            algorithm.IV = rdb.GetBytes(16);
            return algorithm;
        }

        /* 
     * encryptString
     * provides simple encryption of a string, with a given password
     */

        public static string EncryptString(string clearText, string password)
        {
            SymmetricAlgorithm algorithm = getAlgorithm(password);
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            var ms = new MemoryStream();
            var cs = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(clearBytes, 0, clearBytes.Length);
            cs.Close();
            return Convert.ToBase64String(ms.ToArray());
        }

        /*
     * decryptString
     * provides simple decryption of a string, with a given password
     */

        public static string DecryptString(string cipherText, string password)
        {
            SymmetricAlgorithm algorithm = getAlgorithm(password);
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            var ms = new MemoryStream();
            var cs = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(cipherBytes, 0, cipherBytes.Length);
            cs.Close();
            return Encoding.Unicode.GetString(ms.ToArray());
        }
        #endregion
    }
}
