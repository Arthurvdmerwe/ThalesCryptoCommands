using System;
using System.Collections.Generic;
using Common.Logging;

namespace SwitchLink.Cryptography.TritonCryptography
{
    public class TritonCryptography : BaseCryptography
    {
        private readonly ILog logger = LogManager.GetLogger<TritonCryptography>();
        public Dictionary<string, string> GenerateKeys(string keyType)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = BuildCommandKey(keyType);
            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("TMK", response.Substring(10, 33));

                Response.Add("TMK_Check", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;
        }
        private string BuildCommandKey(String keyTyp)
        {
            logger.Info("Generating Command Key");
            String mode = "0", commandCode = "A0", keyType = keyTyp, keyScheme = "U";

            String message = commandCode;
            message += mode;
            message += keyType;
            message += keyScheme;
            return SendMessage(message);
        }
        public Dictionary<string, string> GenerateKeys_TMK()
        {
            Dictionary<String, String> responseTMK = new Dictionary<string, string>();
            String response = BuildCommandTMK();
            String errorCode = response.Substring(8, 2);

            responseTMK.Add("Header", response.Substring(2, 4));

            responseTMK.Add("ResponseCode", response.Substring(6, 2));

            responseTMK.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                responseTMK.Add("TMK", response.Substring(10, 33));

                responseTMK.Add("TMK_Check", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return responseTMK;
        }
        private string BuildCommandTMK()
        {
            logger.Info("Generating TMK");
            String mode = "0", commandCode = "A0", keyType = "002", keyScheme = "U";

            String message = commandCode;
            message += mode;
            message += keyType;
            message += keyScheme;

            return SendMessage(message);
        }
        public Dictionary<string, string> GenerateKeys_TAK()
        {
            Dictionary<String, String> responseTAK = new Dictionary<string, string>();
            String response = BuildCommandTAK();
            String errorCode = response.Substring(8, 2);

            responseTAK.Add("Header", response.Substring(2, 4));

            responseTAK.Add("ResponseCode", response.Substring(6, 2));

            responseTAK.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                responseTAK.Add("TAK", response.Substring(10, 33));

                responseTAK.Add("TAK_Check", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return responseTAK;
        }   
        private string BuildCommandTAK()
        {
            logger.Info("Generating TAK");
            String mode = "0", commandCode = "A0", keyType = "003", keyScheme = "U";

            String message = commandCode;
            message += mode;
            message += keyType;
            message += keyScheme;
            
            return SendMessage(message);
        }
        public Dictionary<String, String> GenerateTerminalSessionKeys(String terminalMasterKey)
        {
         
            Dictionary<String, String> response = new Dictionary<string, string>();
            String hsmResponse = BuildTerminalPinKey(terminalMasterKey);
           
            String errorCode = hsmResponse.Substring(8, 2);
           
            response.Add("Header", hsmResponse.Substring(2, 4));

            response.Add("ResponseCode", hsmResponse.Substring(6, 2));

            response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                response.Add("TPK_LMK", hsmResponse.Substring(10, 33));

                response.Add("TPK_TMK", hsmResponse.Substring(43, 33));

                response.Add("TPK_CHK", hsmResponse.Substring(76));

            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return response;
        }   
        private string BuildTerminalPinKey(String terminalMasterKey)
        {
            logger.Info("Generating a Terminal Pin Key from a Terminal Master Key");
            String commandCode = "A0", mode = "1", keyType = "002", tmk_zmk_flag = "1", keyScheme = "U", tmk = terminalMasterKey, exportingKeyScheme = "X";

            String message = commandCode;
            message += mode;
            message += keyType;
            message += keyScheme + ';';
            message += tmk_zmk_flag;
            message += tmk;
            message += exportingKeyScheme;
            
            return SendMessage(message);
          
        }

        private string GenerateTerminalPinKey_HC(String terminalMasterKey)
        {
            logger.Info("Generating a Terminal Pin Key from a Terminal Master Key");
            String commandCode = "HC",  tmk = terminalMasterKey, exportingKeyScheme = ";XU";

            String message = commandCode;    
            message += tmk;
            message += exportingKeyScheme;
            return SendMessage(message);

        }

        public Dictionary<string, string> TranslatePIN_TPK_ZMK(string TPK, string ZPK, string pinBlock, string accountNumber)
        {
            Dictionary<String, String> Translate_pin_tdes_response = new Dictionary<string, string>();
            String response = BuildCommandTPK_ZPK(TPK, ZPK, pinBlock, accountNumber);

            String errorCode = response.Substring(8, 2);

            Translate_pin_tdes_response.Add("Header", response.Substring(2, 4));

            Translate_pin_tdes_response.Add("ResponseCode", response.Substring(6, 2));

            Translate_pin_tdes_response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Translate_pin_tdes_response.Add("DestPIN", response.Substring(12, 16));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Translate_pin_tdes_response;
        }
        private string BuildCommandTPK_ZPK(string terminalPinKey, string ZPK, string pin_block, string accountNumber)
        {
            logger.Info("Generating TPK Pin Block");
            String commandCode = "CA", tpk = terminalPinKey, zpk = ZPK, pinBlock = pin_block, pan = accountNumber;

            String message = commandCode;
            message += tpk;
            message += zpk;           
            message += "12"; //maximum pin length
            message += pinBlock;
            message += "01";//source pinblock format
            message += "01";//destination pinblock format
            message += pan;
            return SendMessage(message);
        }

        public Dictionary<string, string> TranslatePIN_TDES_D4(string terminalPinKey, string pinEncryptionKey, string pinBlock, string accountNumber)
        {
            Dictionary<String, String> Translate_pin_tdes_response = new Dictionary<string, string>();
            String response = BuildCommandTPKPinBlock(terminalPinKey, pinEncryptionKey, pinBlock, accountNumber);

            String errorCode = response.Substring(8, 2);

            Translate_pin_tdes_response.Add("Header", response.Substring(2, 4));

            Translate_pin_tdes_response.Add("ResponseCode", response.Substring(6, 2));
            Translate_pin_tdes_response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Translate_pin_tdes_response.Add("DestPIN", response.Substring(10, 16));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Translate_pin_tdes_response;
        }


        private string BuildCommandTPKPinBlock(string terminalPinKey, string pinEncryptionKey, string pin_block, string accountNumber)
        {
            logger.Info("Generating TPK Pin Block");
            String commandCode = "D4", ktp = terminalPinKey, kpe = pinEncryptionKey, pinBlock = pin_block, pan = accountNumber;

            String message = commandCode;
            message += ktp;
            message += kpe;
            message += pinBlock;
            message += pan;
            return SendMessage(message);
        }
    }
}
