using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using Tanker.Crypto;

[assembly: InternalsVisibleTo("Identity.Tests")]

namespace Tanker
{
    public static class Identity
    {
        public static string CreateIdentity(string appId, string appSecret, string userId)
        {
            return Utils.toBase64Json(new SecretPermanentIdentity(appId, appSecret, userId));
        }

        public static string CreateProvisionalIdentity(string appId, string email)
        {
            return Utils.toBase64Json(new SecretProvisionalIdentity(appId, email));
        }

        private static string GetPublicIdentity(SecretPermanentIdentity identity)
        {
            var publicIdentity = new PublicPermanentIdentity()
            {
                TrustchainId = identity.TrustchainId,
                Value = identity.Value
            };
            return Utils.toBase64Json(publicIdentity);
        }

        private static string GetPublicIdentity(SecretProvisionalIdentity identity)
        {
            var publicIdentity = new PublicProvisionalIdentity(identity);
            return Utils.toBase64Json(publicIdentity);
        }

        public static string GetPublicIdentity(string identity)
        {
            var jObj = Utils.fromBase64Json<Dictionary<string, string>>(identity);
            string targetValue;
            jObj.TryGetValue("target", out targetValue);
            try
            {
                if (targetValue == "user")
                    return GetPublicIdentity(Utils.fromBase64Json<SecretPermanentIdentity>(identity));
                else
                    return GetPublicIdentity(Utils.fromBase64Json<SecretProvisionalIdentity>(identity));
            }
            catch (Newtonsoft.Json.JsonSerializationException)
            {
                throw new ArgumentException("Bad identity format");
            }
        }

        public static string UpgradeIdentity(string identity)
        {
            var jObj = Utils.fromBase64Json<Dictionary<string, string>>(identity);
            string targetValue;
            jObj.TryGetValue("target", out targetValue);
            
            if (targetValue == "email" && !jObj.ContainsKey("private_encryption_key")) {
                var publicIdentity = Utils.fromBase64Json<PublicProvisionalIdentity>(identity);
                publicIdentity.Target = "hashed_email";
                var hashedEmail = CryptoCore.GenericHash(Encoding.UTF8.GetBytes(publicIdentity.Value), 32);
                publicIdentity.Value = Convert.ToBase64String(hashedEmail);
                return Utils.toBase64Json(publicIdentity);
            } else {
                return Utils.toBase64Json(jObj);
            }
        }
    }
}
