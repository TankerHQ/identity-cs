using Newtonsoft.Json;
using System;
using System.Text;
using Tanker.Crypto;

using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;

namespace Tanker
{
    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy))]
    internal class UserToken
    {
        public byte[] DelegationSignature { get; set; }
        public byte[] EphemeralPrivateSignatureKey { get; set; }
        public byte[] EphemeralPublicSignatureKey { get; set; }
        public byte[] UserId { get; set; }
        public byte[] UserSecret { get; set; }

        public UserToken() { }

        public UserToken(string appId, string appSecret, string userId)
        {
            byte[] trustchainIdBuf = Convert.FromBase64String(appId);
            byte[] trustchainPrivateKeyBuf = Convert.FromBase64String(appSecret);

            UserId = CryptoCore.ObfuscateUserId(Encoding.UTF8.GetBytes(userId), trustchainIdBuf);

            var keyPair = CryptoCore.SignKeyPair();
            EphemeralPrivateSignatureKey = keyPair.PrivateKey;
            EphemeralPublicSignatureKey = keyPair.PublicKey;

            byte[] toSign = CryptoCore.ConcatByteArrays(EphemeralPublicSignatureKey, UserId);
            DelegationSignature = CryptoCore.SignDetached(toSign, trustchainPrivateKeyBuf);

            byte[] randomBuf = CryptoCore.RandomBytes(CryptoCore.UserSecretSize - 1);
            byte[] hash = CryptoCore.GenericHash(CryptoCore.ConcatByteArrays(randomBuf, UserId), CryptoCore.CheckHashBlockSize);
            UserSecret = CryptoCore.ConcatByteArrays(randomBuf, new byte[] { hash[0] });
        }
    }
}
