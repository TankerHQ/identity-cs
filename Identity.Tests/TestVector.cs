using System;
using System.Text;
using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;

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
        private static readonly byte[] HashedUserId = Crypto.CryptoCore.ObfuscateUserId(
            Encoding.UTF8.GetBytes(UserId), Convert.FromBase64String(TrustchainID));
        private const string PermanentIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0=";
        private const string ProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5pbyIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS09jQUNkMzhLNk4wcSttRlU9IiwicHJpdmF0ZV9lbmNyeXB0aW9uX2tleSI6IjRRQjVUV212Y0JyZ2V5RERMaFVMSU5VNnRicUFPRVE4djlwakRrUGN5YkE9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSIsInByaXZhdGVfc2lnbmF0dXJlX2tleSI6IlVtbll1dmRUYUxZRzBhK0phRHBZNm9qdzQvMkxsOHpzbXJhbVZDNGZ1cVJidEFSQUc3MFZkeGNpazZDcnJhMC9BR0xJVUJ1bFBXc0N1NFBTSDgydE1BPT0ifQ==";
        private const string PublicIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9";
        private const string PublicProvisionalIdentity = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJlbWFpbCIsInZhbHVlIjoiYnJlbmRhbi5laWNoQHRhbmtlci5pbyIsInB1YmxpY19lbmNyeXB0aW9uX2tleSI6Ii8yajRkSTNyOFBsdkNOM3VXNEhoQTV3QnRNS09jQUNkMzhLNk4wcSttRlU9IiwicHVibGljX3NpZ25hdHVyZV9rZXkiOiJXN1FFUUJ1OUZYY1hJcE9ncTYydFB3Qml5RkFicFQxckFydUQwaC9OclRBPSJ9";

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
        public void ValidPublicProvisionalIdentity()
        {
            var identity = Utils.fromBase64Json<PublicProvisionalIdentity>(PublicProvisionalIdentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(TrustchainID));
            Assert.That(identity.Target, Is.EqualTo("email"));
            Assert.That(identity.Value, Is.EqualTo(UserEmail));
            Assert.That(identity.PublicSignatureKey, Is.EqualTo(Convert.FromBase64String("W7QEQBu9FXcXIpOgq62tPwBiyFAbpT1rAruD0h/NrTA=")));
            Assert.That(identity.PublicEncryptionKey, Is.EqualTo(Convert.FromBase64String("/2j4dI3r8PlvCN3uW4HhA5wBtMKOcACd38K6N0q+mFU=")));
            Assert.That(Utils.toBase64Json(identity), Is.EqualTo(PublicProvisionalIdentity));
        }
    }
}