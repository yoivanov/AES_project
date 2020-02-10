using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionTest
{

    class ManagedAesSample
    {
        public static string VisualizeInHex(byte[] bytes)
        {
            return string.Join("", bytes.Select(x => x.ToString("X2")));
        }


        public static string VisualizeInMonkey(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            // Create a new AesManaged.    
            using (AesManaged aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;

                // Create encryptor    
                Console.WriteLine("[AES VERIFY] SIZE OF KEY IN PLACE " + Key.Length);
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);

                // Create MemoryStream    
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream    
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data    
            return encrypted;
        }


        public static byte[] EncryptAesManaged(string raw, byte[] key)
        {
            byte[] encrypted = { };

            try
            {
                // Create Aes that generates a new key and initialization vector (IV).    
                // Same key must be used in encryption and decryption    
                using (AesManaged aes = new AesManaged())
                {
                    // Initialization vector only maters in crypto chain mode (CBC)
                    // We will be working with electronic code book mode ()
                    byte[] Key = key;
                    byte[] IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                    // Encrypt string 
                    encrypted = Encrypt(raw, Key, IV);
                    
                }

            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
            
            return encrypted;
        }


        // There is a decryption method if needed
        static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Create AesManaged    
            using (AesManaged aes = new AesManaged())
            {
                // Create a decryptor    
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }
    }
}