using System.Text;

namespace BCryptPbkdf.Net.Tests;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void BasicTest()
    {
        byte[] expectedResult = [188, 118, 150, 169, 99, 249, 181, 39, 247, 12, 185, 91, 141, 44, 206, 254, 200, 141, 242, 2, 218, 198, 168, 101, 93, 58, 150, 112, 241, 187, 208, 39, 29, 229, 39, 107, 63, 2, 109, 161, 180, 124, 160, 177, 120, 80, 75, 9];
        byte[] password = Encoding.UTF8.GetBytes("qwerty");
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        int rounds = 64;

        byte[] key = BCryptPbkdf.Hash(password, salt, rounds, 32 + 16);

        Assert.That(key, Is.EqualTo(expectedResult));
    }
}