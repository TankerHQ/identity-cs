using System;

namespace Tanker
{
    namespace Crypto
    {
        public static class CryptoCore
        {
            public const int BlockHashSize = 32;
            public const int CheckHashBlockSize = 16;
            public const int UserSecretSize = 32;
            private const int AppSecretSize = 64;
            private const int PublicKeySize = 32;
            private const int AuthorSize = 32;
            private const int AppCreationNature = 1;

            public static byte[] ConcatByteArrays(byte[] a, byte[] b)
            {
                byte[] res = new byte[a.Length + b.Length];
                System.Buffer.BlockCopy(a, 0, res, 0, a.Length);
                System.Buffer.BlockCopy(b, 0, res, a.Length, b.Length);
                return res;
            }

            public static byte[] FromHex(string hexString)
            {
                int numChars = hexString.Length;
                byte[] res = new byte[numChars / 2];
                for (int i = 0; i < numChars; i += 2)
                {
                    res[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
                }
                return res;
            }

            public static byte[] GenericHash(byte[] message, int size)
            {
                return Sodium.GenericHash.Hash(message, null, size);
            }

            internal static byte[] ObfuscateUserId(byte[] userId, byte[] trustchainId)
            {
                var toHash = ConcatByteArrays(userId, trustchainId);
                return GenericHash(toHash, BlockHashSize);
            }

            internal static byte[] GenerateAppID(byte[] appSecret)
            {
                var publicKey = new byte[PublicKeySize];
                Array.Copy(appSecret, AppSecretSize - PublicKeySize, publicKey, 0, PublicKeySize);
                byte[] start = new byte[1 + AuthorSize];
                start[0] = AppCreationNature;
                var toHash = ConcatByteArrays(start, publicKey);
                return GenericHash(toHash, BlockHashSize);
            }

            public static KeyPair SignKeyPair()
            {
                var sodiumKeyPair = Sodium.PublicKeyAuth.GenerateKeyPair();
                KeyPair res = new KeyPair();
                res.PrivateKey = sodiumKeyPair.PrivateKey;
                res.PublicKey = sodiumKeyPair.PublicKey;
                return res;
            }

            public static KeyPair EncKeyPair()
            {
                var sodiumKeyPair = Sodium.PublicKeyBox.GenerateKeyPair();
                KeyPair res = new KeyPair();
                res.PrivateKey = sodiumKeyPair.PrivateKey;
                res.PublicKey = sodiumKeyPair.PublicKey;
                return res;
            }

            public static byte[] RandomBytes(int size)
            {
                return Sodium.SodiumCore.GetRandomBytes(size);
            }

            public static byte[] SignDetached(byte[] message, byte[] privateKey)
            {
                var signature = Sodium.PublicKeyAuth.SignDetached(message, privateKey);
                return signature;
            }

            public static bool VerifySignDetached(byte[] message, byte[] signature, byte[] publicKey)
            {
                var ok = Sodium.PublicKeyAuth.VerifyDetached(signature, message, publicKey);
                return ok;
            }

            public static bool ByteArrayCompare(byte[] left, byte[] right)
            {
                if (left.Length != right.Length)
                {
                    return false;
                }
                for (int i = 0; i < left.Length; i++)
                {
                    if (!left[i].Equals(right[i]))
                    {
                        return false;
                    }
                }
                return true;
            }
        }
    }
}
