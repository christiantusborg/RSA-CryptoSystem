using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSA_CryptoSystem
{
    public class RsaCryptosystem
    {

        // Members:
        // RSA Key components (just the three I'm using, there is more...)
        // ReSharper disable once RedundantDefaultMemberInitializer
        private BigInteger _d = null;
        // ReSharper disable once RedundantDefaultMemberInitializer
        private BigInteger _exponent = null;
        // ReSharper disable once RedundantDefaultMemberInitializer
        private BigInteger _modulus = null;

        // .NET RSA class, for loading and creating key pairs
        private readonly RSACryptoServiceProvider _rsaCryptosystem = new RSACryptoServiceProvider();

        // flags, is the keys has been loaded yet?
        private bool _isPrivateKeyLoaded = false;
        // ReSharper disable once RedundantDefaultMemberInitializer
        private bool _isPublicKeyLoaded = false;

        public bool IsPrivateKeyLoaded
        { get { return _isPrivateKeyLoaded; } }

        public bool IsPublicKeyLoaded
        { get { return _isPublicKeyLoaded; } }


        private void LoadKeyFromXml(string path, RsaKeyType rsaKeyType)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("File not exists: " + path);
            // Using the .NET RSA class to load a key from an Xml file, and populating the relevant members
            // of my class with it's RSAParameters
            try
            {
                _rsaCryptosystem.FromXmlString(File.ReadAllText(path));
                RSAParameters rsaParams = _rsaCryptosystem.ExportParameters(rsaKeyType == RsaKeyType.Private);

                if (rsaKeyType == RsaKeyType.Private)
                {
                    _d = new BigInteger(rsaParams.D); // This parameter is only for private key'
                    _isPrivateKeyLoaded = true;
                }
                else
                {
                    _isPublicKeyLoaded = true;
                }
                _modulus = new BigInteger(rsaParams.Modulus);
                _exponent = new BigInteger(rsaParams.Exponent);

            }
            // Examle for the proper use of try - catch blocks: Informing the main app where and why the Exception occurred
            catch (XmlSyntaxException ex)  // Not an xml file
            {
                string excReason = "Exception occurred at LoadKeyFromXml(), Selected file is not a valid xml file.";
                Debug.WriteLine(excReason + " Exception Message: " + ex.Message);
                throw new Exception(excReason, ex);
            }
            catch (CryptographicException ex)  // Not a Key file
            {
                string excReason = "Exception occurred at LoadKeyFromXml(), Selected xml file is not a public key file.";
                Debug.WriteLine(excReason + " Exception Message: " + ex.Message);
                throw new Exception(excReason, ex);
            }
            catch (Exception ex)  // other exception, hope the ex.message will help
            {
                string excReason = "General Exception occurred at LoadKeyFromXml().";
                Debug.WriteLine(excReason + " Exception Message: " + ex.Message);
                throw new Exception(excReason, ex);
            }
        }

        public void LoadPublicFromXml(string publicPath)
        {
            LoadKeyFromXml(publicPath, RsaKeyType.Public);

        }

        public void LoadPrivateFromXml(string privatePath)
        {
            LoadKeyFromXml(privatePath, RsaKeyType.Private);
        }

        // Encrypt data using private key
        public byte[] PrivateEncryption(byte[] data)
        {
            if (!IsPrivateKeyLoaded)  // is the private key has been loaded?
                throw new CryptographicException
                    ("Private Key must be loaded before using the Private Encryption method!");

            // Converting the byte array data into a BigInteger instance
            BigInteger bnData = new BigInteger(data);

            // (bnData ^ D) % Modulus - This Encrypt the data using the private Exponent: D
            BigInteger encData = bnData.modPow(_d, _modulus);
            return encData.getBytes();
        }

        // Encrypt data using public key
        public byte[] PublicEncryption(byte[] data)
        {
            if (!IsPublicKeyLoaded)  // is the public key has been loaded?
                throw new CryptographicException
                    ("Public Key must be loaded before using the Public Encryption method!");

            // Converting the byte array data into a BigInteger instance
            BigInteger bnData = new BigInteger(data);

            // (bnData ^ Exponent) % Modulus - This Encrypt the data using the public Exponent
            BigInteger encData = bnData.modPow(_exponent, _modulus);
            return encData.getBytes();
        }

        // Decrypt data using private key (for data encrypted with public key)
        public byte[] PrivateDecryption(byte[] encryptedData)
        {
            if (!IsPrivateKeyLoaded)  // is the private key has been loaded?
                throw new CryptographicException
                    ("Private Key must be loaded before using the Private Decryption method!");

            // Converting the encrypted data byte array data into a BigInteger instance
            BigInteger encData = new BigInteger(encryptedData);

            // (encData ^ D) % Modulus - This Decrypt the data using the private Exponent: D
            BigInteger bnData = encData.modPow(_d, _modulus);
            return bnData.getBytes();
        }

        // Decrypt data using public key (for data encrypted with private key)
        public byte[] PublicDecryption(byte[] encryptedData)
        {
            if (!IsPublicKeyLoaded)  // is the public key has been loaded?
                throw new CryptographicException
                    ("Public Key must be loaded before using the Public Deccryption method!");

            // Converting the encrypted data byte array data into a BigInteger instance
            BigInteger encData = new BigInteger(encryptedData);

            // (encData ^ Exponent) % Modulus - This Decrypt the data using the public Exponent
            BigInteger bnData = encData.modPow(_exponent, _modulus);
            return bnData.getBytes();
        }

        // Implementation of IDisposable interface,
        // allow you to use this class as: using(RSAEncryption rsa = new RSAEncryption()) { ... }
        public void Dispose()
        {
            _rsaCryptosystem.Clear();
        }

    }
}
