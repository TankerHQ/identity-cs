using System;
using System.Text;
using Newtonsoft.Json;
using Tanker.Crypto;
using NUnit.Framework;

namespace Tanker
{
    public static class Helpers
    {
        public static string TrustchainId => "AzES0aJwDCej9bQVY9AUMZBCLdX0msEc/TJ4DOhZaQs=";
        public static string TrustchainPrivateKey => "cBAq6A00rRNVTHicxNHdDFuq6LNUo6gAz58oKqy9CGd054sGkfPYgXftRCRLfqxeiaoRwQCNLIKxdnuKuf1RAA==";
        public static string TrustchainPublicKey => "dOeLBpHz2IF37UQkS36sXomqEcEAjSyCsXZ7irn9UQA=";
        public static string UserId => "steve@tanker.io";

        public static string GenerateTestToken()
        {
            var token = new UserToken(TrustchainId, TrustchainPrivateKey, UserId);
            return Utils.toBase64Json(token);
        }

        public static bool CheckSignature(byte[] ephemeralPublicSignatureKey, byte[] userId, byte[] signature)
        {
            var trustchainPublicKey = Convert.FromBase64String(Helpers.TrustchainPublicKey);
            var signedData = CryptoCore.ConcatByteArrays(ephemeralPublicSignatureKey, userId);
            return CryptoCore.VerifySignDetached(signedData, signature, trustchainPublicKey);
        }

        public static bool CheckUserSecret(byte[] hashedUserId, byte[] userSecret)
        {
            Assume.That(hashedUserId.Length, Is.EqualTo(CryptoCore.BlockHashSize));
            Assume.That(userSecret.Length, Is.EqualTo(CryptoCore.UserSecretSize));

            var truncatedUserSecret = userSecret;
            Array.Resize(ref truncatedUserSecret, CryptoCore.UserSecretSize - 1);
            byte[] toHash = CryptoCore.ConcatByteArrays(truncatedUserSecret, hashedUserId);

            byte[] control = CryptoCore.GenericHash(toHash, CryptoCore.CheckHashBlockSize);
            return userSecret[CryptoCore.UserSecretSize - 1] == control[0];
        }

        public static byte[] CorruptBuffer(byte[] buffer)
        {
            var res = new byte[buffer.Length];
            buffer.CopyTo(res, 0);
            res[0] = 1;
            return res;
        }
    }
}