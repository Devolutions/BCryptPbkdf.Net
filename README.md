# BCryptPbkdf.Net

A pure C# implementation of bcrypt_pbkdf, used to derive passwords for OpenSSH keys. 

# How to use
```c#
byte[] password = Encoding.UTF8.GetBytes("password");
byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]; // Use a random salt
int rounds = 64;

byte[] key = BCryptPbkdf.Hash(password, salt, rounds, 32);
```