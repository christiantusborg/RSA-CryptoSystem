using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using RSA_CryptoSystem;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace RSA_CryptoSystem.Tests
{
    [TestClass()]
    public class RsaCryptosystemTests
    {
        [TestMethod()]

        public void PublicEncryptionAndPrivateDecryption()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string privateKey = rsa.ToXmlString(true);
            File.WriteAllText("PrivateKey.xml", privateKey);
            string publicKey = rsa.ToXmlString(false);
            File.WriteAllText("PublicKey.xml", publicKey);
            //Encrypt PublicEncryption Decrypt: PrivateDecryption
            RsaCryptosystem rsaCryptosystem = new RsaCryptosystem();

            rsaCryptosystem.LoadPrivateFromXml("PrivateKey.xml");
            rsaCryptosystem.LoadPublicFromXml("PublicKey.xml");
            byte[] message = Encoding.UTF8.GetBytes("Hello World");

            byte[] encMessage = rsaCryptosystem.PublicEncryption(message);
            byte[] decMessage = rsaCryptosystem.PrivateDecryption(encMessage);
            Assert.AreNotEqual(message,decMessage);

            encMessage = rsaCryptosystem.PrivateEncryption(message);
            decMessage = rsaCryptosystem.PublicDecryption(encMessage);
            Assert.AreNotEqual(message, decMessage);
        }
    }
}
