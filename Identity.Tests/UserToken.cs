using NUnit.Framework;
using System;

namespace Tanker.Tests
{
    [TestFixture]
    class UserTokenTest
    {
        [Test]
        public void SignatureAndUserSecretAreValid()
        {
            string encodedToken = Helpers.GenerateTestToken();
            var userToken = Utils.fromBase64Json<UserToken>(encodedToken);

            Assert.That(Helpers.CheckSignature(
                userToken.EphemeralPublicSignatureKey, 
                userToken.UserId,
                userToken.DelegationSignature), Is.True);

            Assert.That(Helpers.CheckUserSecret(userToken.UserId, userToken.UserSecret), Is.True);
        }

        [Test]
        public void InvalidDelegationSignature()
        {
            string encodedToken = Helpers.GenerateTestToken();
            var userToken = Utils.fromBase64Json<UserToken>(encodedToken);

            var invalidDelegationSignature = Helpers.CorruptBuffer(userToken.DelegationSignature);

            Assert.That(Helpers.CheckSignature(
                userToken.EphemeralPublicSignatureKey,
                userToken.UserId,
                invalidDelegationSignature), Is.False);
        }

        [Test]
        public void InvalidUserSecret()
        {
            string encodedToken = Helpers.GenerateTestToken();
            var userToken = Utils.fromBase64Json<UserToken>(encodedToken);

            var invalidUserSecret = Helpers.CorruptBuffer(userToken.UserSecret);
            Assert.That(Helpers.CheckUserSecret(userToken.UserId, invalidUserSecret), Is.False);
        }

    }
}