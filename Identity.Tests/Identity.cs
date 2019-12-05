using System;
using System.Text;
using NUnit.Framework;
using System.Linq;
using Tanker;

namespace Tanker.Tests
{
    [TestFixture]
    public class IdentityTest
    {
        [Test]
        public void CreateIdentityHappy()
        {
            string sidentity = Identity.CreateIdentity(Helpers.TrustchainId, Helpers.TrustchainPrivateKey, Helpers.UserId);
            var identity = Utils.fromBase64Json<SecretPermanentIdentity>(sidentity);
            Assert.That(identity.TrustchainId, Is.EqualTo(Helpers.TrustchainId));
            Assert.That(Helpers.CheckUserSecret(identity.Value, identity.UserSecret), Is.True);
            Assert.That(Helpers.CheckSignature(identity.EphemeralPublicSignatureKey, identity.Value, identity.DelegationSignature), Is.True);
        }

        [Test]
        public void CreateIdentityInvalidSignature()
        {
            string sidentity = Identity.CreateIdentity(Helpers.TrustchainId, Helpers.TrustchainPrivateKey, Helpers.UserId);
            var identity = Utils.fromBase64Json<SecretPermanentIdentity>(sidentity);
            Assert.That(Helpers.CheckSignature(identity.EphemeralPublicSignatureKey,
            identity.Value,
            Helpers.CorruptBuffer(identity.DelegationSignature)), Is.False);
        }

        [Test]
        public void CreateIdentityMismatchingAppID()
        {
            string mistmatchingAppID = "rB0/yEJWCUVYRtDZLtXaJqtneXQOsCSKrtmWw+V+ysc=";
            Assert.That(() => Identity.CreateIdentity(mistmatchingAppID, Helpers.TrustchainPrivateKey, Helpers.UserId), Throws.ArgumentException);
        }

        [Test]
        public void ProvisionalIdentitiesAreDifferent()
        {
            string aliceSidentity = Identity.CreateProvisionalIdentity(Helpers.TrustchainId, "alice@emai.ls");
            var aliceIdentity = Utils.fromBase64Json<SecretProvisionalIdentity>(aliceSidentity);
            string bobSidentity = Identity.CreateProvisionalIdentity(Helpers.TrustchainId, "bob@emai.ls");
            var bobIdentity = Utils.fromBase64Json<SecretProvisionalIdentity>(bobSidentity);

            Assert.That(aliceIdentity.PublicEncryptionKey, Is.Not.EqualTo(bobIdentity.PublicEncryptionKey));
            Assert.That(aliceIdentity.PublicSignatureKey, Is.Not.EqualTo(bobIdentity.PublicSignatureKey));
        }

        [Test]
        public void PublicIdentityMatchesProvisionalIdentity()
        {
            var sAliceIdentity = Identity.CreateProvisionalIdentity(Helpers.TrustchainId, "alice@emai.ls");
            var sPublicIdentity = Identity.GetPublicIdentity(sAliceIdentity);

            var aliceProvisional = Utils.fromBase64Json<SecretProvisionalIdentity>(sAliceIdentity);
            var alicePublic = Utils.fromBase64Json<PublicProvisionalIdentity>(sAliceIdentity);

            Assert.That(alicePublic.TrustchainId, Is.EqualTo(aliceProvisional.TrustchainId));
            Assert.That(alicePublic.Target, Is.EqualTo("email"));
            Assert.That(alicePublic.PublicEncryptionKey, Is.EqualTo(aliceProvisional.PublicEncryptionKey));
            Assert.That(alicePublic.PublicSignatureKey, Is.EqualTo(aliceProvisional.PublicSignatureKey));
        }

        [Test]
        public void PublicIdentityMatchesPermanentIdentity()
        {
            var sAliceIdentity = Identity.CreateIdentity(Helpers.TrustchainId, Helpers.TrustchainPrivateKey, Helpers.UserId);
            var sPublicIdentity = Identity.GetPublicIdentity(sAliceIdentity);

            var alicePermanent = Utils.fromBase64Json<SecretPermanentIdentity>(sAliceIdentity);
            var alicePublic = Utils.fromBase64Json<PublicPermanentIdentity>(sAliceIdentity);

            Assert.That(alicePublic.TrustchainId, Is.EqualTo(alicePermanent.TrustchainId));
            Assert.That(alicePublic.Target, Is.EqualTo("user"));
            Assert.That(alicePublic.Value, Is.EqualTo(alicePermanent.Value));
        }

        [Test]
        public void PublicIdentityfromBadIdentity()
        {
            var json = Encoding.ASCII.GetBytes("{'target': 'stuff'}");
            Assert.That(() => Identity.GetPublicIdentity(Convert.ToBase64String(json)), Throws.ArgumentException);
        }

        [Test]
        public void UpgradeGoodUserToken()
        {
            var token = Helpers.GenerateTestToken();
            var sidentity = Identity.UpgradeUserToken(Helpers.TrustchainId, Helpers.UserId, token);
            var identity = Utils.fromBase64Json<SecretPermanentIdentity>(sidentity);

            Assert.That(identity.TrustchainId, Is.EqualTo(Helpers.TrustchainId));
            Assert.That(Helpers.CheckSignature(identity.EphemeralPublicSignatureKey, identity.Value, identity.DelegationSignature), Is.True);
            Assert.That(Helpers.CheckUserSecret(identity.Value, identity.UserSecret), Is.True);
        }

        [Test]
        public void UpgradeUserTokenBaduserID()
        {
            var token = Helpers.GenerateTestToken();
            Assert.That(
                () => Identity.UpgradeUserToken(Helpers.TrustchainId, "eve@tanker.io", token),
            Throws.ArgumentException);
        }
    }
}