using System;
using System.Security.Cryptography;

namespace BCryptPbkdf.Net
{
    public static class BCryptPbkdf
    {
        /// <summary>
        /// Hashes the specified password using bcrypt_pbkdf.
        /// </summary>
        /// <param name="password">
        /// The password to hash.
        /// </param>
        /// <param name="salt">
        /// The password salt.
        /// </param>
        /// <param name="rounds">
        /// The number of PBKDF iterations. The higher it is, the slower the hashing is and the stronger the hash is.
        /// </param>
        /// <param name="outputLength">
        /// Number of bytes to output.
        /// </param>
        /// <returns>
        /// The bcrypt_pbkdf hash of the password.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Throws when the password or salt is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Throws when there is less then two rounds.
        /// Throws when the password, salt or input length in empty.
        /// </exception>
        public static byte[] Hash(byte[] password, byte[] salt, int rounds, int outputLength)
        {
            // Check parameters
            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (salt is null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            if (rounds < 1 || password.Length <= 0 || salt.Length <= 0 || outputLength <= 0)
            {
                throw new ArgumentException("Invalid arguments for PBKDF");
            }

            byte[] output = new byte[outputLength];
            byte[] accumulator = new byte[Const.BCRYPT_HASH_SIZE];

            int stride = (outputLength + accumulator.Length - 1) / accumulator.Length;
            int amt = (outputLength + stride - 1) / stride;

            using (SHA512 sha512 = SHA512.Create())
            {
                // Prehash password for size normalization
                byte[] sha2Pass = sha512.ComputeHash(password);

                // Loop here to fill the full output if the output size is larger then the bcrypt hash size
                for (uint currentBlockNumber = 1; outputLength > 0; currentBlockNumber++)
                {
                    byte[] currentIterationBytes = new byte[sizeof(uint)];
                    EndiannessHelper.EncodeToBigEndian(currentIterationBytes, 0, currentBlockNumber);

                    // First round salt is input salt | current block number
                    sha512.Initialize();
                    sha512.TransformBlock(salt, 0, salt.Length, salt, 0);
                    sha512.TransformFinalBlock(currentIterationBytes, 0, currentIterationBytes.Length);
                    byte[] sha2Salt = sha512.Hash;

                    byte[] bcryptOutput = BCryptHash(sha2Pass, sha2Salt);
                    Array.Copy(bcryptOutput, accumulator, accumulator.Length);

                    for (int r = 1; r < rounds; r++)
                    {
                        // PBKDF rounds
                        sha512.Initialize();
                        sha512.TransformFinalBlock(bcryptOutput, 0, bcryptOutput.Length);
                        sha2Salt = sha512.Hash;

                        bcryptOutput = BCryptHash(sha2Pass, sha2Salt);

                        // XOR the bcrypt output into the accumulator
                        for (int i = 0; i < accumulator.Length; i++)
                        {
                            accumulator[i] ^= bcryptOutput[i];
                        }
                    }

                    // Output key material
                    // Instead of outputing from left to right, this PBKDF2 variation fills 
                    //   the output blocks by slices.
                    // TODO: See if we can avoid a copy
                    amt = Math.Min(amt, outputLength);
                    int currentKeyOutput = 0;

                    for (; currentKeyOutput < amt; currentKeyOutput++)
                    {
                        int dest = currentKeyOutput * stride + ((int)currentBlockNumber - 1);
                        if (dest >= output.Length)
                        {
                            break;
                        }
                        output[dest] = accumulator[currentKeyOutput];
                    }
                    outputLength -= currentKeyOutput;
                }

                return output;
            };
        }

        /// <summary>
        /// Modified BCrypt implementation with 32 bytes output.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private static byte[] BCryptHash(byte[] password, byte[] salt)
        {
            // Initial value is a Nothing Up My Sleeve constant
            // Note that this constant is longer for bcrypt_pbkdf then regular bcrypt
            byte[] ciphertext = System.Text.Encoding.UTF8.GetBytes(Const.BCRYPT_PLAINTEXT);

            // Initialize the state.
            // This is also a standard deviation, as it uses a salt, which isn't the case with regular Blowfish.
            Blowfish blf = new Blowfish(password, salt);

            // Key Expansion
            // This is the slow part of BCrypt
            for (int i = 0; i < Const.BCRYPT_ROUNDS; i++)
            {
                blf.KeySchedule(salt);
                blf.KeySchedule(password);
            }

            // Parse the byte array as an array of big endian words
            // TODO: Precompute
            uint[] ciphertextWords = new uint[Const.BCRYPT_HASH_SIZE / 4];

            for (int i = 0; i < ciphertextWords.Length; i++)
            {
                ciphertextWords[i] = EndiannessHelper.DecodeFromBigEndian(ciphertext, i * 4);
            }

            // Encrypt the ciphertext over and over to get the BCrypt hash
            for (int i = 0; i < Const.BCRYPT_ROUNDS; i++)
            {
                ciphertextWords = blf.Encrypt(ciphertextWords);
            }

            // Encode the words as little endian into a byte array to output
            for (int i = 0; i < ciphertextWords.Length; i++)
            {
                EndiannessHelper.EncodeToLittleEndian(ciphertext, i * 4, ciphertextWords[i]);
            }

            return ciphertext;
        }
    }
}