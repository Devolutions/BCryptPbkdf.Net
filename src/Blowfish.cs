namespace BCryptPbkdf.Net
{
    internal class Blowfish
    {
        // Permutation table
        private uint[] P;

        // Substitution table
        private uint[,] S;

        /// <summary>
        /// Initialize the blowfish instance using only a key.
        /// </summary>
        /// <param name="key"></param>
        public Blowfish(byte[] key)
        {
            Initialize();
            KeySchedule(key);
        }

        /// <summary>
        /// Initialize the blowfish instance using a key and a salt. This is not a standard Blowfish function.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        public Blowfish(byte[] key, byte[] salt)
        {
            Initialize();
            KeySchedule(key, salt);
        }

        /// <summary>
        /// Initialize the Blowfish state using standardized values, derived from Pi.
        /// </summary>
        private void Initialize()
        {
            P = (uint[])Const.PERMUTATION_TABLE_INIT.Clone();
            S = (uint[,])Const.SUBSTITUTION_TABLE_INIT.Clone();
        }

        /// <summary>
        /// Encrypts the data. You must call this with an even-sized uint array, as this class does not handle the endianness
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public uint[] Encrypt(uint[] data)
        {
            // TODO: Remove copies
            // Process block by block in ECB
            for (int i = 0; i < data.Length; i += 2)
            {
                uint[] block = { data[i], data[i + 1] };

                EncryptBlock(block);

                data[i] = block[0];
                data[i + 1] = block[1];
            }

            return data;
        }

        /// <summary>
        /// Process the state using a key. This is public because this is used directly by Bcrypt.
        /// </summary>
        /// <param name="key"></param>
        public void KeySchedule(byte[] key)
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
                P[i + 1] = block[1];
            }

            // Process the S table using the key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    EncryptBlock(block);

                    S[i, j] = block[0];
                    S[i, j + 1] = block[1];
                }
            }
        }

        /// <summary>
        /// Process the state using a key and a salt.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        private void KeySchedule(byte[] key, byte[] salt)
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
                P[i + 1] = block[1];
            }

            // Process the S table using the key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    block[0] ^= ExtractWord(salt, ref index);
                    block[1] ^= ExtractWord(salt, ref index);

                    EncryptBlock(block);

                    S[i, j] = block[0];
                    S[i, j + 1] = block[1];
                }
            }
        }

        /// <summary>
        /// Encrypt a block of data.
        /// You must pass an array of 2 uints to this.
        /// </summary>
        /// <param name="block"></param>
        private void EncryptBlock(uint[] block)
        {
            // Encrypts one block.
            // TODO: Avoid copies
            uint left = block[0];
            uint right = block[1];

            left ^= P[0];

            // Feistel network
            // TODO: Unroll?
            for (int i = 1; i < Const.BLOWFISH_ROUNDS + 1; i++)
            {
                right ^= Round(left) ^ P[i];

                // Invert the blocks
                (left, right) = (right, left);
            }

            block[0] = right ^ P[P.Length - 1];
            block[1] = left;
        }

        /// <summary>
        /// The Blowfish's Fiestel network round function
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint Round(uint x)
        {
            // Substitution table
            return (
                S[0, x >> 24] +
                S[1, x >> 16 & 0xFF] ^
                S[2, x >> 8 & 0xFF]) +
                S[3, x & 0xFF];
        }

        /// <summary>
        /// Extract a Big Endian uint from a byte array, while looping the counter when reaching the end of the data.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="current"></param>
        /// <returns></returns>
        private static uint ExtractWord(byte[] data, ref int current)
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
