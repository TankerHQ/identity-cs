using System;
using System.Text;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using Tanker.Crypto;

namespace Tanker.Tests
{
    internal class IdentityComparer : EqualityComparer<SecretPermanentIdentity>
    {
        public override bool Equals(SecretPermanentIdentity x, SecretPermanentIdentity y)
        {
            if (x == null && y == null)
                return true;
            if (x == null || y == null)
                return false;
            return x.DelegationSignature.SequenceEqual(y.DelegationSignature) &&
            x.EphemeralPrivateSignatureKey.SequenceEqual(y.EphemeralPrivateSignatureKey) &&
            x.EphemeralPublicSignatureKey.SequenceEqual(y.EphemeralPublicSignatureKey) &&
            x.Target == y.Target &&
            x.TrustchainId == y.TrustchainId &&
            x.UserSecret.SequenceEqual(y.UserSecret) &&
            x.Value.SequenceEqual(y.Value);
        }

        public override int GetHashCode(SecretPermanentIdentity identity)
        {
            return identity.Value.GetHashCode() & identity.DelegationSignature.GetHashCode();
        }
    }

    [TestFixture]
    public class TestVectors
    {
        private const string TrustchainID =
        "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4=";
        private const string PrivateKey =
        "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ==";
        private const string PublicKey = "r6oz1Rpl3dsMGu8te0LT02YZ/G8W9NeQmQv3uGSO/jE=";
        private const string UserId = "b_eich";
        private const string UserEmail = "brendan.eich@tanker.io";
        private const string UserPhone = "+33611223344";
        private static readonly byte[] HashedUserId = Crypto.CryptoCore.ObfuscateUserId(
            Encoding.UTF8.GetBytes(UserId), Convert.FromBase64String(TrustchainID));
        private const string PermanentIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0=";
        private const string ProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5pbyIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS09jQUNkMzhLNk4wcSttRlU9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6IjRRQjVUV212Y0JyZ2V5RERMaFVMSU5VNnRicUFPRVE4djlwakRrUGN5YkE9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSIsInByaXZhdGVfc2lnbmF0dXJlX2tleSI6IlVtbll1dmRUYUxZRzBhK0phRHBZNm9qdzQvMkxsOHpzbXJhbVZDNGZ1cVJidEFSQUc3MFZkeGNpazZDcnJhMC9BR0xJVUJ1bFBXc0N1NFBTSDgydE1BPT0ifQ==";
        private const string PublicIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9";
        private const string OldPublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5pbyIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS09jQUNkMzhLNk4wcSttRlU9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSJ9";
        private const string PublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJoYXNoZWRfZW1haWwiLCJ2YWx1ZSI6IjB1MmM4dzhFSVpXVDJGelJOL3l5TTVxSWJFR1lUTkRUNVNrV1ZCdTIwUW89IiwicHVibGljX2VuY3J5cHRpb25fa2V5IjoiLzJqNGRJM3I4UGx2Q04zdVc0SGhBNXdCdE1LT2NBQ2QzOEs2TjBxK21GVT0iLCJwdWJsaWNfc2lnbmF0dXJlX2tleSI6Ilc3UUVRQnU5RlhjWElwT2dxNjJ0UHdCaXlGQWJwVDFyQXJ1RDBoL05yVEE9In0=";
        private const string PhoneNumberProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJwaG9uZV9udW1iZXIiLCJ2YWx1ZSI6IiszMzYxMTIyMzM0NCIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Im42bTlYNUxmMFpuYXo4ZjArc2NoTElCTm0rcGlQaG5zWXZBdlh3MktFQXc9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6InRWVFM5bkh4cjJNZFZ1VFI1Y2x3dzBFWGJ3aXM4SGl4Z1BJTmJRSngxVTQ9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJqcklEaWdTQ25BaTNHbDltSUFTbEFpU2hLQzdkQkxGVVpQOUN4TEdzYkg4PSIsInByaXZhdGVfc2lnbmF0dXJlX2tleSI6IlFIcWNMcjhicjZNM2JQblFtUWczcStxSENycDA1RGJjQnBMUGFUWlkwYTZPc2dPS0JJS2NDTGNhWDJZZ0JLVUNKS0VvTHQwRXNWUmsvMExFc2F4c2Z3PT0ifQ==";
        private const string PhoneNumberPublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJwaG9uZV9udW1iZXIiLCJ2YWx1ZSI6IkplYWlRQWg4eDdqY2lvVTJtNGloeStDc0hKbHlXKzRWVlNTczVTSEZVVHc9IiwicHVibGljX2VuY3J5cHRpb25fa2V5IjoibjZtOVg1TGYwWm5hejhmMCtzY2hMSUJObStwaVBobnNZdkF2WHcyS0VBdz0iLCJwdWJsaWNfc2lnbmF0dXJlX2tleSI6ImpySURpZ1NDbkFpM0dsOW1JQVNsQWlTaEtDN2RCTEZVWlA5Q3hMR3NiSDg9In0=";

        [Test]
        public void ValidPermanentIdentity()
        {
            var identity = Utils.fromBase64Json<SecretPermanentIdentity>(PermanentIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("user"));
            Assert.That(identity.Value, Is.EqualTo(HashedUserId));
            Assert.That(identity.DelegationSignature, Is.EqualTo(Convert.FromBase64String("U9WQolCvRyjT8oR2PQmd1WXNCi0qmL12hNrtGabYREWiry52kWx1AgYzkLxH6gpo3MiA9r++zhnmoYdEJ0+JCw==")));
            Assert.That(identity.EphemeralPublicSignatureKey, Is.EqualTo(Convert.FromBase64String("Xh3i0xDTpr3HXtB2Q517QKv3azNzXLLXMdJDTSH4bd4=")));
            Assert.That(identity.EphemeralPrivateSignatureKey, Is.EqualTo(Convert.FromBase64String("jEDT4wQCc1DFwodXNPHFClndTPnFuFmXhBt+isKU4ZpeHeLTENOmvcde0HZDnXtAq/drM3Ncstcx0kNNIfht3g==")));
            Assert.That(identity.UserSecret, Is.EqualTo(Convert.FromBase64String(@"7FSf/n0e76QT3s0DkvetRVVJhXZGEjOxj5EWAFexvjI=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PermanentIdentity));
        }

        [Test]
        public void ValidProvisionalIdentity()
        {
            var identity = Utils.fromBase64Json<SecretProvisionalIdentity>(ProvisionalIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("email"));
            Assert.That(identity.Value, Is.EqualTo(UserEmail));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=")));
            Assert.That(identity.PrivateSignatureKey, Is.EqualTo(Convert.FromBase64String("UmnYuvdTaLYG0a+JaDpY6ojw4/2Ll8zsmramVC4fuqRbtARAG70Vdxcik6Crra0/AGLIUBulPWsCu4PSH82tMA==")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=")));
            Assert.That(identity.PrivateEncryptionKey, Is.EqualTo(Convert.FromBase64String(@"4QB5TWmvcBrgeyDDLhULINU6tbqAOEQ8v9pjDkPcybA=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(ProvisionalIdentity));
        }

        [Test]
        public void ValidPublicIdentity()
        {
            var identity = Utils.fromBase64Json<PublicPermanentIdentity>(PublicIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("user"));
            Assert.That(identity.Value, Is.EqualTo(HashedUserId));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PublicIdentity));
        }

        [Test]
        public void ValidOldPublicProvisionalIdentity()
        {
            var identity = Utils.fromBase64Json<PublicProvisionalIdentity>(OldPublicProvisionalIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("email"));
            Assert.That(identity.Value, Is.EqualTo(UserEmail));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(OldPublicProvisionalIdentity));
        }

        [Test]
        public void ValidPublicProvisionalIdentity()
        {
            var identity = Utils.fromBase64Json<PublicProvisionalIdentity>(PublicProvisionalIdentity);
            var hashedEmail = Convert.ToBase64String(CryptoCore.GenericHash(Encoding.UTF8.GetBytes(UserEmail), 32));

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("hashed_email"));
            Assert.That(identity.Value, Is.EqualTo(hashedEmail));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PublicProvisionalIdentity));
        }

        [Test]
        public void ValidPhoneNumberProvisionalIdentity()
        {
            var identity = Utils.fromBase64Json<SecretProvisionalIdentity>(PhoneNumberProvisionalIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("phone_number"));
            Assert.That(identity.Value, Is.EqualTo(UserPhone));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("jrIDigSCnAi3Gl9mIASlAiShKC7dBLFUZP9CxLGsbH8=")));
            Assert.That(identity.PrivateSignatureKey, Is.EqualTo(Convert.FromBase64String("QHqcLr8br6M3bPnQmQg3q+qHCrp05DbcBpLPaTZY0a6OsgOKBIKcCLcaX2YgBKUCJKEoLt0EsVRk/0LEsaxsfw==")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("n6m9X5Lf0Znaz8f0+schLIBNm+piPhnsYvAvXw2KEAw=")));
            Assert.That(identity.PrivateEncryptionKey, Is.EqualTo(Convert.FromBase64String("tVTS9nHxr2MdVuTR5clww0EXbwis8HixgPINbQJx1U4=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PhoneNumberProvisionalIdentity));
        }

        [Test]
        public void ValidPhoneNumberPublicProvisionalIdentity()
        {
            var privIdentity = Utils.fromBase64Json<SecretProvisionalIdentity>(PhoneNumberProvisionalIdentity);
            var identity = Utils.fromBase64Json<PublicProvisionalIdentity>(PhoneNumberPublicProvisionalIdentity);
            var hashedPhone = CryptoCore.HashProvisionalValue(UserPhone, privIdentity.PrivateSignatureKey);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("phone_number"));
            Assert.That(identity.Value, Is.EqualTo(hashedPhone));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("jrIDigSCnAi3Gl9mIASlAiShKC7dBLFUZP9CxLGsbH8=")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("n6m9X5Lf0Znaz8f0+schLIBNm+piPhnsYvAvXw2KEAw=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PhoneNumberPublicProvisionalIdentity));
            Assert.That(Identity.GetPublicIdentity(PhoneNumberProvisionalIdentity), Is.EqualTo(PhoneNumberPublicProvisionalIdentity));
        }

        [Test]
        public void UpgradeProvisionalIdentity()
        {
            var upgraded = Identity.UpgradeIdentity(OldPublicProvisionalIdentity);
            Assert.That(upgraded, Is.EqualTo(PublicProvisionalIdentity));
        }
    }
}
