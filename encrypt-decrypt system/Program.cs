using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace encrypt_decrypt_system
{
    internal class Program
    {
        public static string Encrypt(string plainText, string keyString, int mode, string IV)
        {
            switch(mode)
            {
                case 1:
                {
                    byte[] src = Encoding.UTF8.GetBytes(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;

                    using (ICryptoTransform encrypt = aes.CreateEncryptor(key, null))
                    {
                        byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                        encrypt.Dispose();
                        return Convert.ToBase64String(dest);
                    }
                }
                case 2:
                {
                    byte[] src = Encoding.UTF8.GetBytes(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    byte[] ccc = Encoding.UTF8.GetBytes(IV);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;

                    using (ICryptoTransform encrypt = aes.CreateEncryptor(key, ccc))
                    {
                        byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                        encrypt.Dispose();
                        return Convert.ToBase64String(dest);
                    }
                }
                case 3:
                {
                    byte[] src = Encoding.UTF8.GetBytes(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    byte[] ccc = Encoding.UTF8.GetBytes(IV);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.Mode = CipherMode.CFB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;

                    using (ICryptoTransform encrypt = aes.CreateEncryptor(key, ccc))
                    {
                        byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                        encrypt.Dispose();
                        return Convert.ToBase64String(dest);
                    }
                }
                default:
                    return "Something went wrong";
            }
        }

        public static string Decrypt(string plainText, string keyString,int mode, string IV)
        {
            switch(mode)
            {
                case 1:
                {
                    byte[] src = Convert.FromBase64String(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.KeySize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.ECB;
                    using (ICryptoTransform decrypt = aes.CreateDecryptor(key, null))
                    {
                        byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                        decrypt.Dispose();
                        return Encoding.UTF8.GetString(dest);
                    }
                }
                case 2:
                {
                    byte[] src = Convert.FromBase64String(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    byte[] ccc = Encoding.UTF8.GetBytes(IV);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.KeySize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;
                    using (ICryptoTransform decrypt = aes.CreateDecryptor(key, ccc))
                    {
                        byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                        decrypt.Dispose();
                        return Encoding.UTF8.GetString(dest);
                    }
                }
                case 3:
                {
                    byte[] src = Convert.FromBase64String(plainText);
                    byte[] key = Encoding.ASCII.GetBytes(keyString);
                    byte[] ccc = Encoding.UTF8.GetBytes(IV);
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.KeySize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CFB;
                    using (ICryptoTransform decrypt = aes.CreateDecryptor(key, ccc))
                    {
                        byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                        decrypt.Dispose();
                        return Encoding.UTF8.GetString(dest);
                    }
                }
                default:
                    return "Something went wrong";
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("Choose one:");
            Console.WriteLine("-1- input plain text from keyboard");
            Console.WriteLine("-2- read plain text from file");
            int input = Convert.ToInt32(Console.ReadLine());
            string plainText;
            
            switch (input)
            {
                case 1:
                {
                    Console.WriteLine("Enter plain text:");
                    plainText = Console.ReadLine();
                } 
                    break;
                case 2:
                {
                    using (StreamReader readText = new StreamReader("plainText.txt"))
                    {
                        plainText = readText.ReadLine();
                    }
                }
                    break;
                default: 
                    Console.WriteLine("Wrong input");
                    return;
            }
            
            
            
            Console.WriteLine("Enter secret key:");
            string secreteKey = Console.ReadLine();
            
            Console.WriteLine("Enter IV:");
            string ccc = Console.ReadLine();

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
                {
                    string roundtrip = Encrypt(plainText, secreteKey, mode, ccc);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", plainText);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                    //Write original and encrypted text to file
                    using (StreamWriter writeText = new StreamWriter("plainText.txt"))
                    {
                        writeText.WriteLine(plainText);
                        writeText.WriteLine(roundtrip);
                        //writeText.Close();
                    }
                }
                    break;
                case 2:
                {
                    string roundtrip = Decrypt(plainText, secreteKey, mode, ccc);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", plainText);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                    //Write original and decrypted text to file
                    using (StreamWriter writeText = new StreamWriter("plainText.txt"))
                    {
                        writeText.WriteLine(plainText);
                        writeText.WriteLine(roundtrip);
                        //writeText.Close();
                    }
                }
                    break;
                default: 
                    Console.WriteLine("Wrong input");
                    break;
            }
        }
    }
}