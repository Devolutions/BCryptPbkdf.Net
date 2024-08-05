﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace BCryptPbkdf
{
    static internal class EndiannessHelper
    {
        public static void EncodeToBigEndian(uint x, Span<byte> output)
        {
            if (BitConverter.IsLittleEndian)
            {
                output[0] = (byte)(x >> 24);
                output[1] = (byte)(x >> 16);
                output[2] = (byte)(x >> 8);
                output[3] = (byte)x;
            }
            else
            {
                new Span<byte>(BitConverter.GetBytes(x)).CopyTo(output);
            }
        }

        public static Span<byte> EncodeToLittleEndian(Span<uint> input)
        {
            if (!BitConverter.IsLittleEndian)
            {
                byte[] output = new byte[input.Length * 4];

                for(int i = 0; i < input.Length; i++)
                {
                    uint x = input[i];

                    output[i * 4] = (byte)x;
                    output[i * 4 + 1] = (byte)(x >> 8);
                    output[i * 4 + 2] = (byte)(x >> 16);
                    output[i * 4 + 3] = (byte)(x >> 24);
                }

                return new Span<byte>(output);
            }
            else
            {
                return MemoryMarshal.AsBytes(input);
            }
        }
    }
}
