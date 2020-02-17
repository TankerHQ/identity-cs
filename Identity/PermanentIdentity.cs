using Tanker.Crypto;

using Newtonsoft.Json;
using System.Text;
using System;

using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;

namespace Tanker
{
    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy), ItemRequired = Required.Always)]
    internal class SecretPermanentIdentity
    {
        public byte[] DelegationSignature { get; set; }
        public byte[] EphemeralPrivateSignatureKey { get; set; }
        public byte[] EphemeralPublicSignatureKey { get; set; }
        public byte[] UserSecret { get; set; }
        public string TrustchainId { get; set; }

        public string Target { get; set; } = "user";

        public byte[] Value { get; set; }

        public SecretPermanentIdentity() { }

        public SecretPermanentIdentity(string appId, string appSecret, string userId)
        {
            TrustchainId = appId;
            byte[] trustchainIdBuf = Convert.FromBase64String(TrustchainId);
            byte[] trustchainPrivateKeyBuf = Convert.FromBase64String(appSecret);

            var generatedAppID = CryptoCore.GenerateAppID(trustchainPrivateKeyBuf);
            if (!CryptoCore.ByteArrayCompare(generatedAppID, trustchainIdBuf))
            {
                throw new ArgumentException("App ID and app secret mismatch");
            }

            Value = CryptoCore.ObfuscateUserId(Encoding.UTF8.GetBytes(userId), trustchainIdBuf);

            var keyPair = CryptoCore.SignKeyPair();
            EphemeralPrivateSignatureKey = keyPair.PrivateKey;
            EphemeralPublicSignatureKey = keyPair.PublicKey;

            byte[] toSign = CryptoCore.ConcatByteArrays(EphemeralPublicSignatureKey, Value);
            DelegationSignature = CryptoCore.SignDetached(toSign, trustchainPrivateKeyBuf);

            byte[] randomBuf = CryptoCore.RandomBytes(CryptoCore.UserSecretSize - 1);
            byte[] hash = CryptoCore.GenericHash(CryptoCore.ConcatByteArrays(randomBuf, Value), CryptoCore.CheckHashBlockSize);
            UserSecret = CryptoCore.ConcatByteArrays(randomBuf, new byte[] { hash[0] });
        }
    }

    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy))]
    internal class PublicPermanentIdentity
    {
        public string TrustchainId { get; set; }

        public byte[] Value { get; set; }

        public string Target { get; } = "user";
    }
}