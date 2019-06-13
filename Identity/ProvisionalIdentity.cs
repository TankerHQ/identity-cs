using Newtonsoft.Json;
using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;
using Tanker.Crypto;


namespace Tanker
{
    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy))]
    internal class PublicProvisionalIdentity
    {
        public string TrustchainId { get; set; }
        public string Target { get; set; }
        public string Value { get; set; }
        public byte[] PublicSignatureKey { get; set; }
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
        public string TrustchainId { get; set; }

        public string Target { get; set; } = "email";

        public string Value { get; set; }

        public byte[] PublicEncryptionKey { get; set; }

        public byte[] PrivateEncryptionKey { get; set; }

        public byte[] PublicSignatureKey { get; set; }

        public byte[] PrivateSignatureKey { get; set; }

        public SecretProvisionalIdentity() { }

        public SecretProvisionalIdentity(string trustchainId, string email)
        {
            TrustchainId = trustchainId;
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