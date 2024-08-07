using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace BCryptPbkdf
{
    internal class Blowfish : IDisposable
    {
        // Permutation table
        private readonly uint[] P = new uint[Const.PERMUTATION_TABLE_INIT.Length];

        // Substitution table
        private readonly uint[] S = new uint[4 * 256];

        // Handles used to pin the arrays in memory
        private readonly GCHandle __p_handle;
        private readonly GCHandle __s_handle;

        /// <summary>
        /// Initialize an empty blowfish instance
        /// </summary>
        public Blowfish()
        {
            // Pin the blowfish state to ensure it doesn't get copied
            __p_handle = GCHandle.Alloc(P, GCHandleType.Pinned);
            __s_handle = GCHandle.Alloc(S, GCHandleType.Pinned);
        }

        public void Dispose()
        {
            // Zeroize memory
            Zeroize();

            // Free the pinned buffers
            __p_handle.Free();
            __s_handle.Free();
        }

        /// <summary>
        /// Initialize the Blowfish state using standardized values, derived from Pi.
        /// </summary>
        public void Initialize()
        {
            Const.PERMUTATION_TABLE_INIT.CopyTo(P);
            Const.SUBSTITUTION_TABLE_INIT.CopyTo(S);
        }

        /// <summary>
        /// Zero out the memory of the object to overwrite sensitive information
        /// </summary>
        public void Zeroize()
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.Cast<uint, byte>(P));
            CryptographicOperations.ZeroMemory(MemoryMarshal.Cast<uint, byte>(S));
        }

        /// <summary>
        /// Encrypts the data. You must call this with an even-sized uint array, as this class does not handle the endianness
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public void Encrypt(Span<uint> data)
        {
            // Process block by block in ECB
            for (int i = 0; i < data.Length; i += 2)
            {
                EncryptBlock(data[i..(i + 2)]);
            }
        }

        /// <summary>
        /// Process the state using a key. This is public because this is used directly by Bcrypt.
        /// </summary>
        /// <param name="key"></param>
        public void KeySchedule(ReadOnlySpan<byte> key)
        {
            // Mix the key with the P table
            int index = 0;
            for (int i = 0; i < P.Length; i++)
            {
                P[i] ^= ExtractWord(key, ref index);
            }

            // Process the P table using the key
            index = 0;
            uint[] block = { 0, 0 };
            for (int i = 0; i < P.Length; i += 2)
            {
                EncryptBlock(block);

                P[i] = block[0];
                P[i | 1] = block[1];
            }

            // Process the S table using the key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    EncryptBlock(block);

                    S[i << 8 | j] = block[0];
                    S[i << 8 | j | 1] = block[1];
                }
            }
        }

        /// <summary>
        /// Process the state using a key and a salt.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        public void KeySchedule(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
        {
            // Mix the key with the P table
            int index = 0;
            for (int i = 0; i < P.Length; i++)
            {
                P[i] ^= ExtractWord(key, ref index);
            }

            // Process the P table using the salt
            index = 0;
            uint[] block = { 0, 0 };
            for (int i = 0; i < P.Length; i += 2)
            {
                block[0] ^= ExtractWord(salt, ref index);
                block[1] ^= ExtractWord(salt, ref index);

                EncryptBlock(block);

                P[i] = block[0];
                P[i | 1] = block[1];
            }

            // Process the S table using the key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    block[0] ^= ExtractWord(salt, ref index);
                    block[1] ^= ExtractWord(salt, ref index);

                    EncryptBlock(block);

                    S[i << 8 | j] = block[0];
                    S[i << 8 | j | 1] = block[1];
                }
            }
        }

        /// <summary>
        /// Encrypt a block of data.
        /// You must pass an array of 2 uints to this.
        /// </summary>
        /// <param name="block"></param>
        private void EncryptBlock(Span<uint> block)
        {
            // Encrypts one block.
            uint left = block[0];
            uint right = block[1];

            left ^= P[0];

            // Feistel network
            // The loop is unrolled for performance reason
            right ^= Round(left) ^ P[1];
            left ^= Round(right) ^ P[2];
            right ^= Round(left) ^ P[3];
            left ^= Round(right) ^ P[4];
            right ^= Round(left) ^ P[5];
            left ^= Round(right) ^ P[6];
            right ^= Round(left) ^ P[7];
            left ^= Round(right) ^ P[8];
            right ^= Round(left) ^ P[9];
            left ^= Round(right) ^ P[10];
            right ^= Round(left) ^ P[11];
            left ^= Round(right) ^ P[12];
            right ^= Round(left) ^ P[13];
            left ^= Round(right) ^ P[14];
            right ^= Round(left) ^ P[15];
            left ^= Round(right) ^ P[16];

            block[0] = right ^ P[^1];
            block[1] = left;
        }

        /// <summary>
        /// The Blowfish's Fiestel network round function
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint Round(uint x)
        {
            // Substitution table
            return (
                S[x >> 24] +
                S[0x100 | x >> 16 & 0xFF] ^
                S[0x200 | x >> 8 & 0xFF]) +
                S[0x300 | x & 0xFF];
        }

        /// <summary>
        /// Extract a Big Endian uint from a byte array, while looping the counter when reaching the end of the data.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="current"></param>
        /// <returns></returns>
        private static uint ExtractWord(ReadOnlySpan<byte> data, ref int current)
        {
            uint accumulator = 0;

            for (int i = 0; i < sizeof(uint); i++, current++)
            {
                if (current >= data.Length)
                    current = 0;
                accumulator = (accumulator << 8) | data[current];
            }

            return accumulator;
        }
    }
}
