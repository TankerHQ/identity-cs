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

        public SecretPermanentIdentity(UserToken userToken, string appId = "")
        {
            UserToken = userToken;
            TrustchainId = appId;
        }

        public SecretPermanentIdentity() : this(new UserToken()) { }

        public SecretPermanentIdentity(string appId, string appSecret, string userId)
        : this(new UserToken(appId, appSecret, userId), appId)
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