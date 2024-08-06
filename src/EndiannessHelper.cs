using System;
using System.Buffers.Binary;
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

        public static void FlipEndianeness(Span<uint> input)
        {
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = BinaryPrimitives.ReverseEndianness(input[i]);
            }
        }
    }
}
