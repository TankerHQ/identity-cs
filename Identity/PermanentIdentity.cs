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
        [JsonProperty(Order = 4)]
        public byte[] DelegationSignature { get; set; }
        [JsonProperty(Order = 6)]
        public byte[] EphemeralPrivateSignatureKey { get; set; }
        [JsonProperty(Order = 5)]
        public byte[] EphemeralPublicSignatureKey { get; set; }
        [JsonProperty(Order = 7)]
        public byte[] UserSecret { get; set; }
        [JsonProperty(Order = 1)]
        public string TrustchainId { get; set; }
        [JsonProperty(Order = 2)]
        public string Target { get; set; } = "user";
        [JsonProperty(Order = 3)]
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
        [JsonProperty(Order = 1)]
        public string TrustchainId { get; set; }
        [JsonProperty(Order = 2)]
        public string Target { get; } = "user";
        [JsonProperty(Order = 3)]
        public byte[] Value { get; set; }
    }
}