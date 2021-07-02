using System;
using System.Text;
using Newtonsoft.Json;
using Tanker.Crypto;
using System.Linq;

namespace Tanker
{
    internal static class Utils
    {
        internal static string toBase64Json<T>(T obj)
        {
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(obj)));
        }

        internal static T fromBase64Json<T>(string b64json)
        {
            return JsonConvert.DeserializeObject<T>(Encoding.ASCII.GetString(Convert.FromBase64String(b64json)));
        }

        internal static bool CheckUserId(string appId, byte[] userId, string suserId)
        {
            var trustchainId = Convert.FromBase64String(appId);
            var userId2 = CryptoCore.ObfuscateUserId(Encoding.UTF8.GetBytes(suserId), trustchainId);

            return userId.SequenceEqual(userId2);
        }
    }
}
