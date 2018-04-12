using System;
using System.Collections.Generic;
using System.Text;
using log4net;
using SwitchLink.Cryptography.RSACryptography.Models;
using SwitchLink.Utils;

namespace SwitchLink.Cryptography.RSACryptography
{
    public class TerminalRsa: IEFTPOS_RSA_Cryptography
    {
        private readonly ILog logger = LogManager.GetLogger(typeof(TerminalRsa));
        private readonly RSACryptoBuilder builder = new RSACryptoBuilder();


        //C2 HSM Command
        public Dictionary<string, string> GenerateMacOnMessage(string macKey, byte[] data)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            String response = builder.BuildMacOnMessage(macKey, data);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                result.Add("MAC", response.Substring(10));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;
        }

        public Dictionary<string, string> GenerateMacOnRSACertificate(byte[] certData)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            byte[] responseBytes = builder.BuildMacOnRSACertificate(certData);
            string responseAscii = Encoding.ASCII.GetString(responseBytes);
            string responseHex = HexByteUtils.ByteArrayToHex(responseBytes);

            String errorCode = responseAscii.Substring(8, 2);

            result.Add("Header", responseAscii.Substring(2, 4));

            result.Add("ResponseCode", responseAscii.Substring(6, 2));

            result.Add("ErrorCode", errorCode);

            if (errorCode == "00")
            {
                result.Add("MAC", responseHex.Substring(20, 8));

                result.Add("PublicKey", responseHex.Substring(28));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;
        }


        //HO HSM Command
        public Dictionary<string, string> DecryptPinPadPublicKey(byte[] mac, byte[] manufacturerPublicKey, byte[] signedPinPadPublicKey, string PublicKeyEncoding="01")
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            String response = builder.BuildDecryptPinPadPublicKeyResponse( mac, manufacturerPublicKey, signedPinPadPublicKey, PublicKeyEncoding);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);

            if (errorCode == "00")
            {
                string PPPK = response.Substring(10, response.Length - 8);
                result.Add("PPPK", PPPK);
                result.Add("PPPK_MAC", response.Substring(10 + PPPK.Length));
           
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;
        }



        //H2 HSM Command
        public Dictionary<string, string> GenerateRsaPublicKeyVerificationCode(byte[] publicKeyWithEncoding, string publicKeyEncoding = "02")
        {
            Dictionary<string, string> result = new Dictionary<string, string>();

            String response = builder.BuildPublicKeyVerificationCode(publicKeyWithEncoding, publicKeyEncoding);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));
            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);

            if (errorCode == "00")
            {
                result.Add("PVC", response.Substring(10));
               
            }
            else
            {
                result.Add("ERROR CODE: ", errorCode);
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;
        }

  

        //EI HSM Command


        public RsaCertificate GenerateRsaKeyPair( int keyLength, string publicExponent="03", string keyType = "2",
            string publicKeyEncoding = "01")
        {
            try
            {
                Dictionary<string, string> result = new Dictionary<string, string>();
                byte[] responsebytes = builder.BuildRsaKeyPair(keyLength, publicExponent, keyType, publicKeyEncoding);
                string response = Encoding.ASCII.GetString(responsebytes);
                string hexdatatest = HexByteUtils.ByteArrayToHex(responsebytes);

                String errorCode = response.Substring(8, 2);

                result.Add("Header", response.Substring(2, 4));

                result.Add("ResponseCode", response.Substring(6, 2));

                result.Add("ErrorCode", errorCode);
                logger.Debug("ErrorCode: " + errorCode);

                if (errorCode == "00")
                {
                    int runningPlace = 0;
                    byte[] CertificateData = new byte[responsebytes.Length -10];
                    
                    result.Add("PPPK_PK_Combined", response.Substring(10));
                    Array.Copy(responsebytes, 10, CertificateData, 0, responsebytes.Length - 10);
                    string hexdata = HexByteUtils.ByteArrayToHex(CertificateData);

                    byte[] _PrivateKeyLength = new byte[4];
                    
                    string cert_raw_data2 = BitConverter.ToString(CertificateData).Replace("-", string.Empty);

                    int mod_inidex = cert_raw_data2.IndexOf("0203010001");
                    runningPlace = (mod_inidex / 2) + 5;

                    var _PublicKey = new byte[runningPlace];
             
                    Array.Copy(CertificateData, 0, _PublicKey, 0, runningPlace);
                    Array.Copy(CertificateData, runningPlace, _PrivateKeyLength, 0, 4);

                    string cert_raw_data3 = BitConverter.ToString(_PublicKey).Replace("-", string.Empty);
                    string cert_raw_data4 = BitConverter.ToString(_PrivateKeyLength).Replace("-", string.Empty);

                    string priv_length = Encoding.UTF8.GetString(_PrivateKeyLength);
                    int priv_len = Int32.Parse(priv_length);

                    var _PrivateKey = new byte[priv_len];
           
                    runningPlace += _PrivateKeyLength.Length;
                    Array.Copy(CertificateData, runningPlace, _PrivateKey, 0, priv_len);                  
                    return new RsaCertificate(_PublicKey, _PrivateKey);
                }
                logger.Error("ERROR CODE: " + errorCode);
                return null;
            }
            catch (Exception e)
            {
                logger.Error(e.ToString());
                return null;

            }

        }
        //H8 HSM Command from 9820 NMIC 192 usage
        public Dictionary<string, string> EncryptCrossAcquirerKeyEncryptionKeyunderInitialTransportKey(string publicKeyEncoding, byte[] macPublicKey, byte[] pinPadPublicKey,  byte[] secretKey,  byte[] dataBlock, string randomNumber)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            byte[] responseBytes = builder.BuildCrossAcquirerKeyEncryptionKeyunderInitialTransportKey( publicKeyEncoding, macPublicKey, pinPadPublicKey, secretKey, dataBlock, randomNumber);

            String response = Encoding.ASCII.GetString(responseBytes);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                result.Add("KCA(KTI)", response.Substring(10, 33));

                result.Add("KCA(LMK)", response.Substring(43,33));

                result.Add("DTS", response.Substring(76, 10));

                result.Add("PPSN", response.Substring(86, 16));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;

        }

        /// <summary>
        /// Input - KIA
        /// Output  - TMK1, TMK2, PPASN
        /// CO HSM Command 
        /// </summary>
        /// <param name="acquirerInitilisationKey">KIA Generated previously</param>
        /// <returns></returns>
        public Dictionary<string, string> GenerateInitialTerminalMasterKeys(string acquirerInitilisationKey)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            String response = builder.BuildInitialTerminalMasterKeys(acquirerInitilisationKey);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {

                //TMK 1
                result.Add("TMK1(LMK)", response.Substring(10, 33));

                result.Add("TMK1(KIA)", response.Substring(43, 33));

                result.Add("TMK1 CHECK", response.Substring(76, 6));

                //TMK 2
                result.Add("TMK2(LMK)", response.Substring(88, 33));

                result.Add("TMK2(KIA)", response.Substring(121, 33));

                result.Add("TMK2 CHECK", response.Substring(154, 6));

                //PPASN
                result.Add("PPASN(LMK)", response.Substring(160, 16));

                result.Add("PPASN(KIA)", response.Substring(176, 16));
                
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;

        }

       

        //C6 HSM Command
        public Dictionary<string, string> GenerateRandomNumber()
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            String response = builder.BuildRandomNumber();
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                result.Add("RandomNumber", response.Substring(10));

            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;

        }

        //C8 HSM COmmand
        /// <summary>
        /// Generates a KIA from the KCA
        /// </summary>
        /// <param name="crossAcqiuirerKeyEncryptingKey">KCA under LMK 14-15</param>
        /// <param name="acquirerInstitutionIdentificationCode"></param>
        /// <returns></returns>
        public Dictionary<string, string> GenerateAnAcquirerMasterKeyEncryptingKey(string crossAcqiuirerKeyEncryptingKey, string acquirerInstitutionIdentificationCode)
        { 
        Dictionary<string, string> result = new Dictionary<string, string>();


            String response = builder.BuildAnAcquirerMasterKeyEncryptingKey(crossAcqiuirerKeyEncryptingKey,  acquirerInstitutionIdentificationCode);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                result.Add("KIA(LMK)", response.Substring(10));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;



        }



        //PK HSM Command
        public Dictionary<string, string> GeneratePinPadAcquirerSecurityNumber(string acquirerInitilisationKey)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            String response = builder.BuildPinPadAcquirerSecurityNumber(acquirerInitilisationKey);
            String errorCode = response.Substring(8, 2);

            result.Add("Header", response.Substring(2, 4));

            result.Add("ResponseCode", response.Substring(6, 2));

            result.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                result.Add("PPPK", response.Substring(10));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return result;
        }

        public Dictionary<string, string> DecryptPinPadPublicKey(byte[] mac, byte[] manufacturerPublicKey, byte[] signedPinPadPublicKey, byte[] AllKeyData, string PublicKeyEncoding = "01")
        {
            throw new NotImplementedException();
        }
    }
}
