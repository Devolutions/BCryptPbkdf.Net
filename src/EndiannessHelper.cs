using System;

namespace BCryptPbkdf
{
    static internal class EndiannessHelper
    {
        public static void EncodeToBigEndian(byte[] output, int offset, uint x)
        {
            if (BitConverter.IsLittleEndian)
            {
                output[offset] = (byte)(x >> 24);
                output[offset + 1] = (byte)(x >> 16);
                output[offset + 2] = (byte)(x >> 8);
                output[offset + 3] = (byte)x;
            }
            else
            {
                byte[] bits = BitConverter.GetBytes(x);

                Array.Copy(bits, 0, output, offset, bits.Length);
            }
        }
        public static void EncodeToLittleEndian(byte[] output, int offset, uint x)
        {
            if (!BitConverter.IsLittleEndian)
            {
                output[offset] = (byte)x;
                output[offset + 1] = (byte)(x >> 8);
                output[offset + 2] = (byte)(x >> 16);
                output[offset + 3] = (byte)(x >> 24);
            }
            else
            {
                byte[] bits = BitConverter.GetBytes(x);

                Array.Copy(bits, 0, output, offset, bits.Length);
            }
        }

        public static uint DecodeFromBigEndian(byte[] x, int offset)
        {
            return (uint)(
                x[offset] << 24 | 
                x[offset + 1] << 16 | 
                x[offset + 2] << 8 | 
                x[offset + 3]);
        }
    }
}
