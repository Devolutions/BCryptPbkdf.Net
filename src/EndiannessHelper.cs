using System;
using System.Runtime.InteropServices;

namespace BCryptPbkdf
{
    static internal class EndiannessHelper
    {
        public static byte[] EncodeToBigEndian(uint x)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] output = new byte[sizeof(uint)];

                output[0] = (byte)(x >> 24);
                output[1] = (byte)(x >> 16);
                output[2] = (byte)(x >> 8);
                output[3] = (byte)x;

                return output;
            }
            else
            {
                return BitConverter.GetBytes(x);
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
