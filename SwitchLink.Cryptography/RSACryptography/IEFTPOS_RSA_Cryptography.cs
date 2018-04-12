using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SwitchLink.Cryptography.RSACryptography.Models;

namespace SwitchLink.Cryptography.RSACryptography
{
    public interface IEFTPOS_RSA_Cryptography
    {
         Dictionary<string, string> GenerateMacOnMessage(string macKey, byte[] data);


        Dictionary<string, string> DecryptPinPadPublicKey(byte[] mac, byte[] manufacturerPublicKey,
            byte[] signedPinPadPublicKey, byte[] AllKeyData, string PublicKeyEncoding = "01");

        Dictionary<string, string> GenerateRsaPublicKeyVerificationCode(byte[] publicKeyWithEncoding,
            string publicKeyEncoding = "01");

        RsaCertificate GenerateRsaKeyPair(int keyLength = 1024, string publicExponent = "03", string keyType = "2", string publicKeyEncoding = "01");

        Dictionary<string, string> EncryptCrossAcquirerKeyEncryptionKeyunderInitialTransportKey(
            string publicKeyEncoding, byte[] macPublicKey, byte[] pinPadPublicKey, byte[] secretKey, byte[] dataBlock,
            string randomNumber);



        Dictionary<string, string> GenerateInitialTerminalMasterKeys(string acquirerInitilisationKey);


        Dictionary<string, string> GenerateAnAcquirerMasterKeyEncryptingKey(string crossAcqiuirerKeyEncryptingKey,
            string acquirerInstitutionIdentificationCode);

        Dictionary<string, string> GeneratePinPadAcquirerSecurityNumber(string acquirerInitilisationKey);

        Dictionary<string, string> GenerateMacOnRSACertificate(byte[] certData);



    }
}
