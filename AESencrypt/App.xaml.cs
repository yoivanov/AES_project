using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace AESencrypt
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    /// 
    public partial class App : Application
    {
        private static AesLib.Aes encryptor;
        private static AesLib.Aes decryptor;
        private static int numberOfRouds;

        public static int NumberOfRounds
        {
            get => numberOfRouds;
        }

        public static bool IsKeyCorrect(string key, int requiredKeyLength)
        {
            if (key.Length == requiredKeyLength)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsDecryptStringCorrect(string decryptString)
        {
            if (decryptString.Length % 16 == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static string ShowKeySchedule()
        {
            return encryptor.ShowSchedule();
        }

        public static string ShowSbox()
        {
            return encryptor.ShowSbox();
        }

        public static string ShowDSbox()
        {
            return decryptor.ShowSbox();
        }

        public static string ShowRcon()
        {
            return encryptor.ShowRcon();
        }

        public static ObservableCollection<byte> ShowStep()
        {
            return encryptor.getMockData();
        }

        public static string ShowRounds()
        {
            return encryptor.ShowRounds();
        }

        public static string ShowDRounds()
        {
            return decryptor.ShowRounds();
        }

        public static string Encryption(string text, string key, AesLib.Aes.KeySize size)
        {
            byte[] keybytes = new byte[16];

            keybytes = Encoding.UTF8.GetBytes(key);

            AesLib.Aes a = new AesLib.Aes(size, keybytes);
            encryptor = a;
            numberOfRouds = a.GetNumberOfRounds();

            byte[] enciphered = a.AESEncypherLong(text);

            string hex = a.VisualizeInHex(enciphered);

            return hex;
        }

        public static string Decryption(string text, string key, AesLib.Aes.KeySize size)
        {
            byte[] keybytes = new byte[16];

            keybytes = Encoding.UTF8.GetBytes(key);

            AesLib.Aes b = new AesLib.Aes(size, keybytes);
            decryptor = b;
            numberOfRouds = b.GetNumberOfRounds();

            byte[] deciphered = b.AESDecypherLong(text);

            b.Dump();

            return Encoding.UTF8.GetString(deciphered);
        }
    }
}
