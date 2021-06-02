using Newtonsoft.Json;
using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;
using Tanker.Crypto;


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
            PublicEncryptionKey = secretIdentity.PublicEncryptionKey;
            PublicSignatureKey = secretIdentity.PublicEncryptionKey;
        }
    }

    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy), ItemRequired = Required.Always)]
    internal class SecretProvisionalIdentity
    {
        [JsonProperty(Order = 1)]
        public string TrustchainId { get; set; }
        [JsonProperty(Order = 2)]
        public string Target { get; set; } = "email";
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

        public SecretProvisionalIdentity(string appId, string email)
        {
            TrustchainId = appId;
            Value = email;

            var encKeys = CryptoCore.EncKeyPair();
            PublicEncryptionKey = encKeys.PublicKey;
            PrivateEncryptionKey = encKeys.PrivateKey;

            var sigKeys = CryptoCore.SignKeyPair();
            PublicSignatureKey = sigKeys.PublicKey;
            PrivateSignatureKey = sigKeys.PrivateKey;
        }
    }


}