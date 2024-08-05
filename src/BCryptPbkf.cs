﻿using System;
using System.Runtime.InteropServices;
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
        public static byte[] Hash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int rounds, int outputLength)
        {
            // Check parameters
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            ArgumentNullException.ThrowIfNull

            if (salt == null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            if (rounds < 1 || password.Length <= 0 || salt.Length <= 0 || outputLength <= 0)
            {
                throw new ArgumentException("Invalid arguments for PBKDF");
            }

            byte[] output = new byte[outputLength];

            int nOutputBlock = (outputLength + Const.BCRYPT_HASH_SIZE - 1) / Const.BCRYPT_HASH_SIZE;

            // Reuse the same blowfish engine for each iteration to avoid unnecessary allocations
            Blowfish blowfish = new Blowfish();
            using SHA512 sha512 = SHA512.Create();

            // Prehash password for size normalization
            byte[] hashedPassword = new byte[Const.SHA512_HASH_SIZE];
            sha512.TryComputeHash(password, hashedPassword, out _);

            // This is the block that will be reused as salt for multiple blocks
            Span<byte> saltBlock = new Span<byte>(new byte[salt.Length + sizeof(uint)]);
            salt.CopyTo(saltBlock);

            byte[] hashedSalt = new byte[Const.SHA512_HASH_SIZE];

            // Loop here to fill the full output if the output size is larger then the bcrypt hash size
            for (uint currentBlockNumber = 0; currentBlockNumber < nOutputBlock; currentBlockNumber++)
            {
                EndiannessHelper.EncodeToBigEndian(currentBlockNumber + 1, saltBlock[^4..]);
                sha512.TryComputeHash(saltBlock, hashedSalt, out _);

                Span<byte> bcryptOutput =  BCryptHash(hashedPassword, hashedSalt, blowfish);

                // Copies output bytes non-linearly
                for(int i = 0; i < output.Length / nOutputBlock; i++)
                {
                    int dest = i * nOutputBlock + (int)currentBlockNumber;
                    output[dest] = bcryptOutput[i];
                }

                for (int r = 1; r < rounds; r++)
                {
                    // PBKDF rounds
                    sha512.TryComputeHash(bcryptOutput, hashedSalt, out _);

                    bcryptOutput = BCryptHash(hashedPassword, hashedSalt, blowfish);

                    // XOR the bcrypt output into the output non-linearly
                    for(int i = 0; i < output.Length / nOutputBlock; i++)
                    {
                        int dest = i * nOutputBlock + (int)currentBlockNumber;
                        output[dest] ^= bcryptOutput[i];
                    }
                }
            }

            return output;
        }

        /// <summary>
        /// Modified BCrypt implementation with 32 bytes output.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private static Span<byte> BCryptHash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Blowfish blf)
        {
            // Initialize the state.
            // This is also a deviation from the standard, as it uses a salt, which isn't the case with regular Blowfish.
            blf.Initialize();
            blf.KeySchedule(password, salt);

            // Key Expansion
            // This is the slow part of BCrypt
            for (int i = 0; i < Const.BCRYPT_ROUNDS; i++)
            {
                blf.KeySchedule(salt);
                blf.KeySchedule(password);
            }

            // The initial plaintext is a standardized constant, which is longer then regular bcrypt.
            // Here it is pre-encoded as big endian unsigned int
            uint[] ciphertextWords = (uint[])Const.BCRYPT_PLAINTEXT.Clone();

            // Encrypt the ciphertext over and over to get the BCrypt hash
            for (int i = 0; i < Const.BCRYPT_ROUNDS; i++)
            {
                blf.Encrypt(ciphertextWords);
            }

            return EndiannessHelper.EncodeToLittleEndian(ciphertextWords);
        }
    }
}