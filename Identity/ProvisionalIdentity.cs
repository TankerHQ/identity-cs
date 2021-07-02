using Newtonsoft.Json;
using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;
using Tanker.Crypto;
using System;
using System.Text;
using System.Linq;

namespace Tanker
{
    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy))]
    internal class PublicProvisionalIdentity
    {
        [JsonProperty(Order = 1)]
        public string TrustchainId { get; set; }
        [JsonProperty(Order = 2)]
        public string Target { get; set; }
        [JsonProperty(Order = 3)]
        public string Value { get; set; }
        [JsonProperty(Order = 5)]
        public byte[] PublicSignatureKey { get; set; }
        [JsonProperty(Order = 4)]
        public byte[] PublicEncryptionKey { get; set; }

        public PublicProvisionalIdentity() { }

        public PublicProvisionalIdentity(SecretProvisionalIdentity secretIdentity)
        {
            TrustchainId = secretIdentity.TrustchainId;
            Target = secretIdentity.Target;
            Value = secretIdentity.Value;
            if (Target == "email") {
                var hashedEmail = CryptoCore.GenericHash(Encoding.UTF8.GetBytes(Value), 32);
                Value = Convert.ToBase64String(hashedEmail);
            } else {
                Value = CryptoCore.HashProvisionalValue(Value, secretIdentity.PrivateSignatureKey);
            }
                Target = "hashed_" + Target;

            PublicEncryptionKey = secretIdentity.PublicEncryptionKey;
            PublicSignatureKey = secretIdentity.PublicSignatureKey;
        }
    }

    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy), ItemRequired = Required.Always)]
    internal class SecretProvisionalIdentity
    {
        private static readonly string[] VALID_TARGETS = {"email", "phone_number"};

        [JsonProperty(Order = 1)]
        public string TrustchainId { get; set; }
        [JsonProperty(Order = 2)]
        public string Target { get; set; }
        [JsonProperty(Order = 3)]
        public string Value { get; set; }
        [JsonProperty(Order = 4)]
        public byte[] PublicEncryptionKey { get; set; }
        [JsonProperty(Order = 5)]
        public byte[] PrivateEncryptionKey { get; set; }
        [JsonProperty(Order = 6)]
        public byte[] PublicSignatureKey { get; set; }
        [JsonProperty(Order = 7)]
        public byte[] PrivateSignatureKey { get; set; }

        public SecretProvisionalIdentity() { }

        public SecretProvisionalIdentity(string appId, string target, string value)
        {

            if (!VALID_TARGETS.Contains(target))
                throw new ArgumentException("Unsupported provisional identity target");

            TrustchainId = appId;
            Target = target;
            Value = value;

            var encKeys = CryptoCore.EncKeyPair();
            PublicEncryptionKey = encKeys.PublicKey;
            PrivateEncryptionKey = encKeys.PrivateKey;

            var sigKeys = CryptoCore.SignKeyPair();
            PublicSignatureKey = sigKeys.PublicKey;
            PrivateSignatureKey = sigKeys.PrivateKey;
        }
    }


}
