using Newtonsoft.Json;
using SnakeCaseStrategy = Newtonsoft.Json.Serialization.SnakeCaseNamingStrategy;


namespace Tanker
{
    [JsonObject(NamingStrategyType = typeof(SnakeCaseStrategy), ItemRequired = Required.Always)]
    internal class SecretPermanentIdentity
    {
        private UserToken UserToken;
        public string TrustchainId { get; set; }

        public string Target { get; set; } = "user";

        public byte[] Value
        {
            get
            {
                return UserToken.UserId;
            }
            set
            {
                UserToken.UserId = value;
            }
        }

        public byte[] DelegationSignature
        {
            get
            {
                return UserToken.DelegationSignature;
            }
            set
            {
                UserToken.DelegationSignature = value;
            }
        }

        public byte[] EphemeralPrivateSignatureKey
        {
            get
            {
                return UserToken.EphemeralPrivateSignatureKey;
            }
            set
            {
                UserToken.EphemeralPrivateSignatureKey = value;
            }
        }

        public byte[] EphemeralPublicSignatureKey
        {
            get
            {
                return UserToken.EphemeralPublicSignatureKey;
            }
            set
            {
                UserToken.EphemeralPublicSignatureKey = value;
            }
        }

        public byte[] UserSecret
        {
            get
            {
                return UserToken.UserSecret;
            }
            set
            {
                UserToken.UserSecret = value;
            }
        }

        public SecretPermanentIdentity(UserToken userToken, string trustchainId = "")
        {
            UserToken = userToken;
            TrustchainId = trustchainId;
        }

        public SecretPermanentIdentity() : this(new UserToken()) { }

        public SecretPermanentIdentity(string trustchainId, string trustchainPrivateKey, string userId)
        : this(new UserToken(trustchainId, trustchainPrivateKey, userId), trustchainId)
        {
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