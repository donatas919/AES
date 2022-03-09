using System;
using System.IO; 
using System.Security.Cryptography;
using System.Text;

namespace encrypt_decrypt_system
{
    internal class Program
    {
        public static string Encrypt(string plainText, string keyString, int mode)
        {
            byte[] cipherData;
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(keyString);
            aes.GenerateIV();
            if (mode == 1)
            {
                aes.Mode = CipherMode.ECB;
                ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, null);
            }
            else if (mode == 2)
            {
                aes.Mode = CipherMode.CBC;
                ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);
            }
            else if (mode == 3)
            {
                aes.Mode = CipherMode.CFB;
            }
            //ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                }

                cipherData = ms.ToArray();
            }

            byte[] combinedData = new byte[aes.IV.Length + cipherData.Length];
            Array.Copy(aes.IV, 0, combinedData, 0, aes.IV.Length);
            Array.Copy(cipherData, 0, combinedData, aes.IV.Length, cipherData.Length);
            return Convert.ToBase64String(combinedData);
        }

        public static string Decrypt(string combinedString, string keyString,int mode)
        {
            string plainText;
            byte[] combinedData = Convert.FromBase64String(combinedString);
            Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(keyString);
            byte[] iv = new byte[aes.BlockSize / 8];
            byte[] cipherText = new byte[combinedData.Length - iv.Length];
            Array.Copy(combinedData, iv, iv.Length);
            Array.Copy(combinedData, iv.Length, cipherText, 0, cipherText.Length);
            aes.IV = iv;
            if (mode == 1)
            {
                aes.Mode = CipherMode.ECB;
            }
            else if (mode == 2)
            {
                aes.Mode = CipherMode.CBC;
            }
            else if (mode == 3)
            {
                aes.Mode = CipherMode.CFB;
            }
            ICryptoTransform decipher = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decipher, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        plainText = sr.ReadToEnd();
                    }
                }

                return plainText;
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Enter plain text:");
            string plainText = Console.ReadLine();
            
            Console.WriteLine("Enter Insert secret key:");
            string secreteKey = Console.ReadLine();

            int x;
            Console.WriteLine("Choose one:");
            Console.WriteLine("-1- encrypt plain text");
            Console.WriteLine("-2- decrypt plain text");

            x = Convert.ToInt32(Console.ReadLine());
            
            Console.WriteLine("Choose cipher mode:");
            Console.WriteLine("-1- ECB");
            Console.WriteLine("-2- CBC");
            Console.WriteLine("-3- CFB");
            int mode = Convert.ToInt32(Console.ReadLine());

            switch(x)
            {
                case 1:
                    string roundtrip = Encrypt(plainText, secreteKey, mode);
                    
                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", plainText);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                    break;
                case 2:
                    string roundtrip01 = Decrypt(plainText, secreteKey, mode);
                    
                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", plainText);
                    Console.WriteLine("Round Trip: {0}", roundtrip01);
                    break;
                default: 
                    Console.WriteLine("Wrong input");
                    break;
            }
        }
    }
}