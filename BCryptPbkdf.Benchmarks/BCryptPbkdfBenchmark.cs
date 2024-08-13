using BenchmarkDotNet.Attributes;
using System.Text;

namespace BCryptPbkdf;

public class BCryptPbkdfBenchmark
{
    byte[] password = Encoding.UTF8.GetBytes("qwerty");
    byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    uint rounds = 64;

    [Benchmark]
    public void BasicTest()
    {
        BCryptPbkdf.Hash(password, salt, rounds, 32 + 16);
    }

    [Benchmark]
    public void BlocksizeTest()
    {
        BCryptPbkdf.Hash(password, salt, rounds, 32);
    }
}