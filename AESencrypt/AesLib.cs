using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Data;
using AESencrypt;

namespace AesLib
{
    public class Aes  // Advanced Encryption Standard
    {

        // ======================
        // GLOBAL VARIABLES
        // ======================

        public enum KeySize { Bits128, Bits192, Bits256 };  // key size, in bits, for construtor
        //public enum Direction { Encrypt, Decrypt };

        //private Direction dir;

        private int keySize;    // key size in 32-bit words.  4, 6, 8.  (128, 192, 256 bits).
        private int numRounds;  // number of rounds. 10, 12, 14.

        private byte[] key;     // the secret key. size will be 4 * keySize
        private byte[,] Sbox;   // Substitution box
        private byte[,] iSbox;  // inverse Substitution box

        private byte[,] keySchedule;  // key schedule array
        private byte[,] Rcon;   // Round constants array
        private byte[,] State;  // State matrix

        private string showRounds;
        private int counter;

        private List<MatrixModel[]> beforeSubBytes;
        private List<MatrixModel[]> afterSubBytes;

        private List<MatrixModel[]> beforeShiftRows;
        private List<MatrixModel[]> afterShiftRows;

        private List<MatrixModel[]> beforeMixColumns;
        private List<MatrixModel[]> afterMixColumns;

        private List<MatrixModel[]> beforeRoundKey;
        private List<MatrixModel[]> afterRoundKey;

        private List<MatrixModel[]> roundKey0;
        private List<MatrixModel[]> roundKeys;


        private void BuildSbox()
        {
            // // populate the Sbox matrix
            this.Sbox = new byte[16, 16] {
                   /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
            /*0*/  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            /*1*/  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            /*2*/  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            /*3*/  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            /*4*/  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            /*5*/  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            /*6*/  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            /*7*/  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            /*8*/  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            /*9*/  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            /*a*/  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            /*b*/  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            /*c*/  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            /*d*/  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            /*e*/  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            /*f*/  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        }  // BuildSbox()

        private void BuildInvSbox()
        {
            // populate the inverse Sbox matrix
            this.iSbox = new byte[16, 16] {
                   /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
            /*0*/  {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            /*1*/  {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            /*2*/  {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            /*3*/  {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            /*4*/  {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            /*5*/  {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            /*6*/  {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            /*7*/  {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            /*8*/  {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            /*9*/  {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            /*a*/  {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            /*b*/  {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            /*c*/  {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            /*d*/  {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            /*e*/  {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            /*f*/  {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };

        }  // BuildInvSbox()

        private void BuildRcon()
        {
            // populate the round constant matrix
            this.Rcon = new byte[11, 4] {
                {0x00, 0x00, 0x00, 0x00},
                {0x01, 0x00, 0x00, 0x00},
                {0x02, 0x00, 0x00, 0x00},
                {0x04, 0x00, 0x00, 0x00},
                {0x08, 0x00, 0x00, 0x00},
                {0x10, 0x00, 0x00, 0x00},
                {0x20, 0x00, 0x00, 0x00},
                {0x40, 0x00, 0x00, 0x00},
                {0x80, 0x00, 0x00, 0x00},
                {0x1b, 0x00, 0x00, 0x00},
                {0x36, 0x00, 0x00, 0x00}
            };
        }  // BuildRcon()

        

        // ======================
        // GETTING VISUAL DATA METHODS
        // ======================


        public MatrixModel[] GetBeforeSubBytes(int index)
        {
             return this.beforeSubBytes.ElementAt(index);
        }

        public MatrixModel[] GetAfterSubBytes(int index)
        {
            return this.afterSubBytes.ElementAt(index);
        }

        public MatrixModel[] GetBeforeShiftRows(int index)
        {
            return this.beforeShiftRows.ElementAt(index);
        }

        public MatrixModel[] GetAfterShiftRows(int index)
        {
            return this.afterShiftRows.ElementAt(index);
        }

        public MatrixModel[] GetBeforeMixColumns(int index)
        {
            return this.beforeMixColumns.ElementAt(index);
        }

        public MatrixModel[] GetAfterMixColumns(int index)
        {
            return this.afterMixColumns.ElementAt(index);
        }

        public MatrixModel[] GetBeforeRoundKey(int index)
        {
            return this.beforeRoundKey.ElementAt(index);
        }

        public MatrixModel[] GetAfterRoundKey(int index)
        {
            return this.afterRoundKey.ElementAt(index);
        }

        public MatrixModel[] GetRoundKeys(int index)
        {
            return this.roundKeys.ElementAt(index);
        }

        public List<SboxModel> GetSbox()
        {
            List<SboxModel> newSbox = new List<SboxModel>();

            for (int r = 0; r < 16; r++)
            {
                SboxModel temp = new SboxModel
                {
                    Col1 = Sbox[r, 0].ToString("x2"),
                    Col2 = Sbox[r, 1].ToString("x2"),
                    Col3 = Sbox[r, 2].ToString("x2"),
                    Col4 = Sbox[r, 3].ToString("x2"),
                    Col5 = Sbox[r, 4].ToString("x2"),
                    Col6 = Sbox[r, 5].ToString("x2"),
                    Col7 = Sbox[r, 6].ToString("x2"),
                    Col8 = Sbox[r, 7].ToString("x2"),
                    Col9 = Sbox[r, 8].ToString("x2"),
                    Col10 = Sbox[r, 9].ToString("x2"),
                    Col11 = Sbox[r, 10].ToString("x2"),
                    Col12 = Sbox[r, 11].ToString("x2"),
                    Col13 = Sbox[r, 12].ToString("x2"),
                    Col14 = Sbox[r, 13].ToString("x2"),
                    Col15 = Sbox[r, 14].ToString("x2"),
                    Col16 = Sbox[r, 15].ToString("x2")
                };

                newSbox.Add(temp);
            }
            return newSbox;
        }

        public List<SboxModel> GetSboxTitles()
        {
            List<SboxModel> temp = new List<SboxModel>();

            temp.Add(new SboxModel()
            {
                Col1 = "0",
                Col2 = "1",
                Col3 = "2",
                Col4 = "3",
                Col5 = "4",
                Col6 = "5",
                Col7 = "6",
                Col8 = "7",
                Col9 = "8",
                Col10 = "9",
                Col11 = "a",
                Col12 = "b",
                Col13 = "c",
                Col14 = "d",
                Col15 = "e",
                Col16 = "f",
            });

            return temp;
        }


        // ======================
        // CONSTRUCTOR METHODS
        // ======================

        private void SetKeySizeNumRounds(KeySize size)
        {
            // setting up key size according to the size of the key chosen
            // block size always = 4 words = 16 bytes = 128 bits for AES

            if (size == KeySize.Bits128)
            {
                this.keySize = 4;   // key size = 4 words = 16 bytes = 128 bits
                this.numRounds = 10;  // rounds for algorithm = 10
            }
            else if (size == KeySize.Bits192)
            {
                this.keySize = 6;   // 6 words = 24 bytes = 192 bits
                this.numRounds = 12;  // rounds for algorithm = 12
            }
            else if (size == KeySize.Bits256)
            {
                this.keySize = 8;   // 8 words = 32 bytes = 256 bits
                this.numRounds = 14; // rounds for algorithm = 14
            }
        }  // set key size

        public int GetNumRounds()
        {
            return numRounds;
        }


        public Aes(KeySize keySize, byte[] keyBytes)
        {
            // AES constructor
            SetKeySizeNumRounds(keySize);
            counter = 0;

            this.key = new byte[this.keySize * 4];  // 16, 24, 32 bytes
            keyBytes.CopyTo(this.key, 0);

            BuildSbox();  // load sboxes into memory
            BuildInvSbox();

            BuildRcon();  // calculate round constants
            KeyExpansion();  // expand the given key into a key schedule

        }  // AES constructor


        // ======================
        // HELPER METHODS
        // ======================


        private void AddRoundKey(int round)
        {

            for (int r = 0; r < 4; ++r)
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = (byte)((int)this.State[r, c] ^ (int)keySchedule[(round * 4) + c, r]);
                }
            }
        }  // AddRoundKey()


        private void SubBytes(byte[,] box)
        {
            for (int r = 0; r < 4; ++r)
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = box[(this.State[r, c] >> 4), (this.State[r, c] & 0x0f)];
                }
            }
        }  // SubBytes


        private void ShiftRows()
        {
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  // copy State into temp
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }

            for (int r = 1; r < 4; ++r)  // copy temp into State
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = temp[r, (c + r) % 4];
                }
            }
        }  // ShiftRows()


        private void InvShiftRows()
        {
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  // copy State into temp
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }
            for (int r = 1; r < 4; ++r)  // copy temp into State
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, (c + r) % 4] = temp[r, c];
                }
            }
        }  // InvShiftRows()


        private void MixColumns()
        {
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  // copy State into temp
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }

            for (int c = 0; c < 4; ++c)  // copy temp into State
            {
                this.State[0, c] =
                    (byte)((int)gfmultby02(temp[0, c]) ^ (int)gfmultby03(temp[1, c]) ^ (int)gfmultby01(temp[2, c]) ^ (int)gfmultby01(temp[3, c]));
                this.State[1, c] =
                    (byte)((int)gfmultby01(temp[0, c]) ^ (int)gfmultby02(temp[1, c]) ^ (int)gfmultby03(temp[2, c]) ^ (int)gfmultby01(temp[3, c]));
                this.State[2, c] =
                    (byte)((int)gfmultby01(temp[0, c]) ^ (int)gfmultby01(temp[1, c]) ^ (int)gfmultby02(temp[2, c]) ^ (int)gfmultby03(temp[3, c]));
                this.State[3, c] =
                    (byte)((int)gfmultby03(temp[0, c]) ^ (int)gfmultby01(temp[1, c]) ^ (int)gfmultby01(temp[2, c]) ^ (int)gfmultby02(temp[3, c]));
            }
        }  // MixColumns


        private void InvMixColumns()
        {
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  // copy State into temp
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }

            for (int c = 0; c < 4; ++c)  // copy temp into State
            {
                this.State[0, c] =
                    (byte)((int)gfmultby0e(temp[0, c]) ^ (int)gfmultby0b(temp[1, c]) ^ (int)gfmultby0d(temp[2, c]) ^ (int)gfmultby09(temp[3, c]));
                this.State[1, c] =
                    (byte)((int)gfmultby09(temp[0, c]) ^ (int)gfmultby0e(temp[1, c]) ^ (int)gfmultby0b(temp[2, c]) ^ (int)gfmultby0d(temp[3, c]));
                this.State[2, c] =
                    (byte)((int)gfmultby0d(temp[0, c]) ^ (int)gfmultby09(temp[1, c]) ^ (int)gfmultby0e(temp[2, c]) ^ (int)gfmultby0b(temp[3, c]));
                this.State[3, c] =
                    (byte)((int)gfmultby0b(temp[0, c]) ^ (int)gfmultby0d(temp[1, c]) ^ (int)gfmultby09(temp[2, c]) ^ (int)gfmultby0e(temp[3, c]));
            }
        }  // InvMixColumns


        private static byte gfmultby01(byte b)
        {
            return b;
        }

        private static byte gfmultby02(byte b)
        {
            if (b < 0x80)
                return (byte)(int)(b << 1);
            else
                return (byte)((int)(b << 1) ^ (int)(0x1b));
        }

        private static byte gfmultby03(byte b)
        {
            return (byte)((int)gfmultby02(b) ^ (int)b);
        }

        private static byte gfmultby09(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)b);
        }

        private static byte gfmultby0b(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(b) ^ (int)b);
        }

        private static byte gfmultby0d(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(gfmultby02(b)) ^ (int)(b));
        }

        private static byte gfmultby0e(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(gfmultby02(b)) ^ (int)gfmultby02(b));
        }


        private void KeyExpansion()
        {
            this.keySchedule = new byte[4 * (numRounds + 1), 4];  // 4 columns of bytes corresponds to a word

            Console.WriteLine("[AES LIB] Creating new key schedule. Size [" + 4 * (numRounds + 1) + ",4]");

            for (int row = 0; row < keySize; row++)
            {

                this.keySchedule[row, 0] = this.key[4 * row];  // array[row, column]
                this.keySchedule[row, 1] = this.key[4 * row + 1];
                this.keySchedule[row, 2] = this.key[4 * row + 2];
                this.keySchedule[row, 3] = this.key[4 * row + 3];

            }


            byte[] temp = new byte[4];

            for (int row = keySize; row < 4 * (numRounds + 1); row++)
            {
                temp[0] = this.keySchedule[row - 1, 0];
                temp[1] = this.keySchedule[row - 1, 1];
                temp[2] = this.keySchedule[row - 1, 2];
                temp[3] = this.keySchedule[row - 1, 3];


                if (row % keySize == 0)
                {
                    // Every 4th word in the array gets complex transformation

                    temp = SubWord(RotWord(temp));

                    temp[0] = (byte)((int)temp[0] ^ (int)this.Rcon[row / keySize, 0]);
                    temp[1] = (byte)((int)temp[1] ^ (int)this.Rcon[row / keySize, 1]);
                    temp[2] = (byte)((int)temp[2] ^ (int)this.Rcon[row / keySize, 2]);
                    temp[3] = (byte)((int)temp[3] ^ (int)this.Rcon[row / keySize, 3]);

                }

                // logical XOR is performed
                this.keySchedule[row, 0] = (byte)((int)this.keySchedule[row - keySize, 0] ^ (int)temp[0]);
                this.keySchedule[row, 1] = (byte)((int)this.keySchedule[row - keySize, 1] ^ (int)temp[1]);
                this.keySchedule[row, 2] = (byte)((int)this.keySchedule[row - keySize, 2] ^ (int)temp[2]);
                this.keySchedule[row, 3] = (byte)((int)this.keySchedule[row - keySize, 3] ^ (int)temp[3]);

            }  // for loop
        }  // KeyExpansion

        private byte[] SubWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = this.Sbox[word[0] >> 4, word[0] & 0x0f];
            result[1] = this.Sbox[word[1] >> 4, word[1] & 0x0f];
            result[2] = this.Sbox[word[2] >> 4, word[2] & 0x0f];
            result[3] = this.Sbox[word[3] >> 4, word[3] & 0x0f];
            return result;
        }

        private byte[] RotWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }




        public void CopyMatrix(byte[,] copyFrom, List<MatrixModel[]> copyTo)
        {
            MatrixModel[] temp = new MatrixModel[4];

            for (int i = 0; i < 4; i++)
            {
                temp[i] = new MatrixModel
                {
                    Col1 = copyFrom[i, 0].ToString("x2"),
                    Col2 = copyFrom[i, 1].ToString("x2"),
                    Col3 = copyFrom[i, 2].ToString("x2"),
                    Col4 = copyFrom[i, 3].ToString("x2"),
                };
            }

            copyTo.Add(temp);
        }


        public void CopyRoundKeys(int round, List<MatrixModel[]> copyTo)
        {
            MatrixModel[] temp = new MatrixModel[4];

            for (int i = 0; i < 4; i++)
            {
                temp[i] = new MatrixModel
                {
                    Col1 = keySchedule[(round * 4) + i, 0].ToString("x2"),
                    Col2 = keySchedule[(round * 4) + i, 1].ToString("x2"),
                    Col3 = keySchedule[(round * 4) + i, 2].ToString("x2"),
                    Col4 = keySchedule[(round * 4) + i, 3].ToString("x2"),
                };
            }

            copyTo.Add(temp);
        }



        // ======================
        // VISUAL METHODS
        // ======================

        public string ShowSchedule()
        {
            return DumpTwoByTwo(this.keySchedule);
        }

        public string ShowSbox()
        {
            return DumpSbox(this.Sbox);
        }

        public string ShowRcon()
        {
            return DumpTwoByTwo(this.Rcon);
        }

        public string ShowRounds()
        {
            return this.showRounds;
        }

        public void Dump()
        {
            Console.WriteLine("\n[AES LIB] Key size = " + keySize + " Number of rounds = " + numRounds);
            Console.WriteLine("\n[AES LIB] The key is \n" + DumpKey());
            Console.WriteLine("\n[AES LIB] The Sbox is \n" + DumpTwoByTwo(Sbox));
            Console.WriteLine("\n[AES LIB] The w array is \n" + DumpTwoByTwo(keySchedule));
            Console.WriteLine("\n[AES LIB] The State array is \n" + DumpTwoByTwo(State));
        }

        public string DumpKey()
        {
            string s = "";
            for (int i = 0; i < key.Length; ++i)
                s += key[i].ToString("x2") + " ";
            return s;
        }

        public string DumpTwoByTwo(byte[,] a)
        {
            string s = "";
            for (int r = 0; r < a.GetLength(0); ++r)
            {
                s += "[" + r + "]" + " ";
                for (int c = 0; c < a.GetLength(1); ++c)
                {
                    s += a[r, c].ToString("x2") + " ";
                }
                s += "\n";
            }
            return s;
        }

        public string DumpSbox(byte[,] a)
        {
            string s = "      [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  [8]  [9]  [a] [b] [c] [d] [e] [f]\n";
            for (int r = 0; r < 10; ++r)
            {
                s += "[ " + r + "]" + " ";
                for (int c = 0; c < 15; ++c)
                {
                    s += a[r, c].ToString("x2") + "  ";
                }
                s += "\n";
            }

            for (char r = 'a'; r < 'g'; ++r)
            {
                s += "[ " + r + "]" + " ";
                for (int c = 0; c < 15; ++c)
                {
                    s += a[r - 87, c].ToString("x2") + "  ";
                }
                s += "\n";
            }

            return s;
        }

        public string VisualizeInHex(byte[] bytes)
        {
            return string.Join("", bytes.Select(x => x.ToString("X2")));
        }


        public string VisualizeInMonkey(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }


        /*  
            ======================
            MAIN ENCRYPTION AND DECRYPTION METHODS
            ======================  
        */


        // encrypt a 16-byte input string (16 symbols)
        public byte[] Encrypt(byte[] input)
        {
            counter++; // counter will show how many times the encryption has been called, for now will show only 1st encryption cycle

            beforeSubBytes = new List<MatrixModel[]>();
            afterSubBytes = new List<MatrixModel[]>();

            beforeShiftRows = new List<MatrixModel[]>();
            afterShiftRows = new List<MatrixModel[]>();

            beforeMixColumns = new List<MatrixModel[]>();
            afterMixColumns = new List<MatrixModel[]>();

            beforeRoundKey = new List<MatrixModel[]>();
            afterRoundKey = new List<MatrixModel[]>();

            roundKey0 = new List<MatrixModel[]>();
            roundKeys = new List<MatrixModel[]>();



            this.State = new byte[4, 4];  // block size is always [4,4] for AES
            byte[] output = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                //  fill the state matrix vertically(!) with the first 16 bytes
                this.State[i % 4, i / 4] = input[i];
            }

            for (int i = 0; i < State.Length; i++)
            {

            }

            if (counter == 1)
            {
                this.showRounds += "\n[AES LIB] First state matrix is";
                this.showRounds += "\n" + DumpTwoByTwo(State);
                
            }


            Console.WriteLine("[AES LIB] First state matrix is");
            Console.WriteLine(DumpTwoByTwo(State));


            // STEP 1 / Round 0 - the first round key is added
            // === Add round key ===
            // Adding the first round key is called key whitening
            CopyRoundKeys(0, roundKey0);
            AddRoundKey(0);

            if (counter == 1)
            {
                this.showRounds += "\n[AES LIB] ROUND 0";
                this.showRounds += "\n" + DumpTwoByTwo(State);
            }

            Console.WriteLine("[AES LIB] ROUND 0");
            Console.WriteLine(DumpTwoByTwo(State));

            for (int round = 1; round < numRounds; round++)  // main loop
            {
                // Done in order:

                // STEP 2 === Byte substitution ===
                CopyMatrix(this.State, beforeSubBytes);
                SubBytes(this.Sbox);
                CopyMatrix(this.State, afterSubBytes);

                // STEP 3 === Shift rows ===
                CopyMatrix(this.State, beforeShiftRows);
                ShiftRows();
                CopyMatrix(this.State, afterShiftRows);

                // STEP 4 === Mix columns ===
                CopyMatrix(this.State, beforeMixColumns);
                MixColumns(); // this can be made in an if statement but the number of checks is not worth it
                CopyMatrix(this.State, afterMixColumns);

                // STEP 5 === Add round key ===
                CopyMatrix(this.State, beforeRoundKey);
                CopyRoundKeys(round, roundKeys);
                AddRoundKey(round);
                CopyMatrix(this.State, afterRoundKey);

                if (counter == 1)
                {
                    this.showRounds += "\n[AES LIB] ROUND " + round;
                    this.showRounds += "\n" + DumpTwoByTwo(State);
                }

                Console.WriteLine("[AES LIB] ROUND " + round);
                Console.WriteLine(DumpTwoByTwo(State));

            }  // main loop


            // STEP 6 / Last Round
            SubBytes(this.Sbox);
            ShiftRows();
            // MIX COLUMNS IS NOT DONE IN THE LAST ITERATION
            AddRoundKey(numRounds);

            if (counter == 1)
            {
                this.showRounds += "\n[AES LIB] LAST ROUND";
                this.showRounds += "\n" + DumpTwoByTwo(State);
            }

            Console.WriteLine("[AES LIB] LAST ROUND");
            Console.WriteLine(DumpTwoByTwo(State));

            // Writing the internal state matrix into the output array
            for (int i = 0; i < 16; i++)
            {
                output[i] = this.State[i % 4, i / 4];
            }

            return output;
        }  // Encrypt Method



        // Encrypts a sring of any length
        public byte[] AESEncypherLong(string text)
        {
            byte[] originalBytes = new byte[16];
            byte[] processedBytes = new byte[16];
            byte[] keybytes = new byte[16];


            List<string> blocks = new List<string>();
            List<byte> encryptedResult = new List<byte>();

            // Splitting the message into blocks
            for (int i = 0; i < text.Length; i = i + 16)
            {
                if (text.Length - i < 16)
                {
                    //if the last block is smaller than our needed chunk size, add the needed number of spaces
                    //blocks.Add(text.Substring(i) + new string((char)0x00, 16 - (text.Length - i)));
                    blocks.Add(text.Substring(i) + new string(' ', 16 - (text.Length - i)));
                }
                else
                {
                    blocks.Add(text.Substring(i, 16));
                }

            }

            //
            // Loop through all 128 bit blocks of the message
            //

            foreach (string block in blocks)
            {
                // splitting string chunks into byte blocks
                byte[] byteBlock = Encoding.UTF8.GetBytes(block);
                processedBytes = this.Encrypt(byteBlock);

                for (int j = 0; j < 16; j++)
                {
                    encryptedResult.Add(processedBytes[j]);
                }

            }

            return encryptedResult.ToArray();

        } // Encrypt Long Method


        // decrypt a 16-byte input string (16 symbols)
        public byte[] Decrypt(byte[] input)  // decipher 16-byte input
        {
            counter++; // counter will show how many times the encryption has been called, for now will show only 1st encryption cycle

            beforeSubBytes = new List<MatrixModel[]>();
            afterSubBytes = new List<MatrixModel[]>();

            beforeShiftRows = new List<MatrixModel[]>();
            afterShiftRows = new List<MatrixModel[]>();

            beforeMixColumns = new List<MatrixModel[]>();
            afterMixColumns = new List<MatrixModel[]>();

            beforeRoundKey = new List<MatrixModel[]>();
            afterRoundKey = new List<MatrixModel[]>();

            roundKey0 = new List<MatrixModel[]>();
            roundKeys = new List<MatrixModel[]>();

            this.State = new byte[4, 4];  // block size is always [4,4] for AES
            byte[] output = new byte[16];

            for (int i = 0; i < 16; ++i)
            {
                this.State[i % 4, i / 4] = input[i];
            }

            Console.WriteLine("First Decryption state matrix is");
            Console.WriteLine(DumpTwoByTwo(State));

            // STEP 1 / Round 0 - the first round key is added in REVERSE
            // === Add round key ===
            // key whitening
            AddRoundKey(numRounds); // starting with the LAST key

            if (counter == 1)
            {
                this.showRounds += "\n[AES LIB] DECRYPTION ROUND 0";
                this.showRounds += "\n" + DumpTwoByTwo(State);
            }

            Console.WriteLine("[AES LIB] DECRYPTION ROUND 0");
            Console.WriteLine(DumpTwoByTwo(State));

            for (int round = numRounds - 1; round > 0; round--)  // main loop
            {
                // Done in order:

                // STEP 2 === Inverse Shift Rows ===
                CopyMatrix(this.State, beforeSubBytes);
                InvShiftRows();
                CopyMatrix(this.State, afterSubBytes);

                // STEP 3 === Inverse Byte substitution ===
                CopyMatrix(this.State, beforeShiftRows);
                SubBytes(this.iSbox);
                CopyMatrix(this.State, afterShiftRows);

                // STEP 4 === Add round key (same in decryption) ===
                CopyMatrix(this.State, beforeMixColumns);
                AddRoundKey(round);
                CopyMatrix(this.State, afterMixColumns);

                // STEP 5 === Inverse Mix columns ===
                CopyMatrix(this.State, beforeRoundKey);
                CopyRoundKeys(round, roundKeys);
                InvMixColumns();
                CopyMatrix(this.State, afterRoundKey);

                if (counter == 1)
                {
                    this.showRounds += "\n[AES LIB] ROUND " + round;
                    this.showRounds += "\n" + DumpTwoByTwo(State);
                }

            }  // main loop

            // STEP 6 / Last Round
            InvShiftRows();
            SubBytes(this.iSbox);
            AddRoundKey(0);

            if (counter == 1)
            {
                this.showRounds += "\n[AES LIB] DECRYPTION LAST ROUND";
                this.showRounds += "\n" + DumpTwoByTwo(State);
            }

            Console.WriteLine("[AES LIB] DECRYPTION LAST ROUND");
            Console.WriteLine(DumpTwoByTwo(State));

            for (int i = 0; i < 16; i++)
            {
                output[i] = this.State[i % 4, i / 4];
            }

            return output;
        }  // Decrypt Method


        public byte[] AESDecypherLong(string text)
        {
            byte[] originalBytes = new byte[16];
            byte[] processedBytes = new byte[16];
            byte[] keybytes = new byte[16];


            List<string> blocks = new List<string>();
            List<byte> encryptedResult = new List<byte>();

            // Splitting the message into blocks
            for (int a = 0; a < text.Length; a = a + 32)
            {
                // two symbols from a decryption input string make one hexadecimal number

                blocks.Add(text.Substring(a, 32));
            }

            //
            // Loop through all 128 bit blocks of the message
            //

            foreach (string block in blocks)
            {
                // splitting string chunks into byte blocks
                byte[] byteBlock = StringToByteArray(block);

                processedBytes = this.Decrypt(byteBlock);

                for (int b = 0; b < 16; b++)
                {
                    encryptedResult.Add(processedBytes[b]);
                }

            }

            return encryptedResult.ToArray();

        } // Decrypt Long Method

        public int GetNumberOfRounds() => this.numRounds;

    }  // class Aes
}  // namespace AesLib
