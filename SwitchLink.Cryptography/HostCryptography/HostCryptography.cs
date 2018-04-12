using System;
using System.Collections.Generic;
using Common.Logging;


namespace SwitchLink.Cryptography.HostCryptography
{
    public class HostCryptography:BaseCryptography
    {
        private readonly ILog logger = LogManager.GetLogger<HostCryptography>();
        public Dictionary<string, string> Generate_KEKr_Validation_Response(string kekr, string krs)
        {
            Dictionary<String, String> kekr_validation_response = new Dictionary<string, string>();
            String response = BuildKekrValidationResponse(kekr, krs);
            String errorCode = response.Substring(8, 2);

            kekr_validation_response.Add("Header", response.Substring(2, 4));

            kekr_validation_response.Add("ResponseCode", response.Substring(6, 2));

            kekr_validation_response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                kekr_validation_response.Add("KRr", response.Substring(10));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return kekr_validation_response;
        }
        public string BuildKekrValidationResponse(string _kekr, string _krs)
        {
            logger.Info("Generating message to build KEKr validation response");
            String commandCode = "E2", kekr = _kekr, krs = _krs;

            String message = commandCode;
            message += kekr;
            message += krs;

            return SendMessage(message);
        }

        public Dictionary<string, string> Generate_KEKs_Validation_Request(string keks)
        {
            Dictionary<String, String> keks_validation_request = new Dictionary<string, string>();
            String response = BuildKeksValidationRequest(keks);
            String errorCode = response.Substring(8, 2);

            keks_validation_request.Add("Header", response.Substring(2, 4));

            keks_validation_request.Add("ResponseCode", response.Substring(6, 2));
            keks_validation_request.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                keks_validation_request.Add("KRs", response.Substring(10, 16));

                keks_validation_request.Add("KRr", response.Substring(26, 16));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            return keks_validation_request;
        }
        public string BuildKeksValidationRequest(string _keks)
        {
            logger.Info("Generating message to build KEKs validation request");
            String commandCode = "E0", keks = _keks;

            String message = commandCode;
            message += keks;
            
            return SendMessage(message);
        }

        public string VerifyMAC(string mac, string message, string length, string key)
        {
            //Dictionary<String, String> keks_validation_request = new Dictionary<string, string>();
            String response = GetMacInfo(mac, message, length, key);
            return response;
        }
        public string GetMacInfo(string mac, string msg, string length, string key)
        {
            logger.Info("Generating message to get MAC Info");

            String message = "C40320";
            message += key;
            message += mac;
            message += length;
            message += msg;
            
            return SendMessage(message);
        }

        public Dictionary<string, string> GenerateRandomNumber()
        {

            Dictionary<String, String> randomNumber = new Dictionary<string, string>();
            String response = GetRandomNumber();
            String errorCode = response.Substring(8, 2);

            randomNumber.Add("Header", response.Substring(2, 4));

            randomNumber.Add("ResponseCode", response.Substring(6, 2));

            randomNumber.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                randomNumber.Add("Random Number:", response.Substring(10, 16));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            return randomNumber;
        }
        public string GetRandomNumber()
        {
            logger.Info("Generating message to get random number");

            string commandCode = "C6";
            String message = commandCode;

            return SendMessage(message);
        }

        public Dictionary<string, string> GenerateSetOfZoneKeys(string keks)
        {
            Dictionary<String, String> zoneKeys = new Dictionary<string, string>();
            String response = GetSetOfZoneKeys(keks);
            String errorCode = response.Substring(8, 2);

            zoneKeys.Add("Header", response.Substring(2, 4));

            zoneKeys.Add("ResponseCode", response.Substring(6, 2));

            zoneKeys.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                zoneKeys.Add("ZPK(LMK)", response.Substring(10, 33));

                zoneKeys.Add("ZPK(ZMK)", response.Substring(43, 33));

                zoneKeys.Add("ZPK Check Value", response.Substring(76, 6));

                zoneKeys.Add("ZAK(LMK)", response.Substring(82, 33));

                zoneKeys.Add("ZAK(ZMK)", response.Substring(115, 33));

                zoneKeys.Add("ZAK Check Value", response.Substring(148, 6));

                zoneKeys.Add("ZEK(LMK)", response.Substring(154, 33));

                zoneKeys.Add("ZEK(ZMK)", response.Substring(187, 33));

                zoneKeys.Add("ZEK Check Value", response.Substring(220, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            return zoneKeys;
        }
        public string GetSetOfZoneKeys(string _keks)
        {
            logger.Info("Generating message to get set of zone keys");
            String commandCode = "OI", keks = _keks;

            String message = commandCode;
            message += keks;
            message += ";HU1;1";

            return SendMessage(message);
        }

        public Dictionary<string, string> TranslateSetOfZoneKeys(string kekr, string zpk, string zak, string zek)
        {
            Dictionary<String, String> translatedZoneKeys = new Dictionary<string, string>();
            String response = GetTranslatedSetOfZoneKeys(kekr, zpk, zak, zek);
            String errorCode = response.Substring(8, 2);

            translatedZoneKeys.Add("Header", response.Substring(2, 4));

            translatedZoneKeys.Add("ResponseCode", response.Substring(6, 2));

            translatedZoneKeys.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                translatedZoneKeys.Add("KCV Processing Flag", response.Substring(10, 1));

                translatedZoneKeys.Add("ZPK(LMK)", response.Substring(11, 33));

                translatedZoneKeys.Add("ZPK Check Value", response.Substring(44, 6));

                translatedZoneKeys.Add("ZAK(LMK)", response.Substring(50, 33));

                translatedZoneKeys.Add("ZAK Check Value", response.Substring(83, 6));

                translatedZoneKeys.Add("ZEK(LMK)", response.Substring(89, 33));

                translatedZoneKeys.Add("ZEK Check Value", response.Substring(122, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            return translatedZoneKeys;
        }
        public string GetTranslatedSetOfZoneKeys(string _kekr, string _zpk, string _zak, string _zek)
        {
            logger.Info("Generating message to get translated set of zone keys");
            String commandCode = "OK", kekr = _kekr, kvcProcessingFlag = "2", zpkFlag = "1", zpk = "H" + _zpk, zakFlag = "1", zak = "H" + _zak, zekFlag = "0", zek = "H" + "11111111111111111111111111111111";

            String message = commandCode;
            message += kekr;
            message += kvcProcessingFlag;
            message += zpkFlag;
            message += zpk;
            message += zakFlag;
            message += zak;
            message += zekFlag;
            message += zek;
            message += ";HU1";
            
            return SendMessage(message);
        }

        public Dictionary<string, string> CalculateMAC_ZAK(string message, string macKey)
        {
            Dictionary<String, String> responseMAC = new Dictionary<string, string>();

            String response = GenerateMAC(message, macKey);

            String errorCode = response.Substring(8, 2);

            responseMAC.Add("Header", response.Substring(2, 4));

            responseMAC.Add("ResponseCode", response.Substring(6, 2));

            responseMAC.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                responseMAC.Add("MAC :", response.Substring(10));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            return responseMAC;
        }
        public string GenerateMAC(string msg, string macKey)
        {
            logger.Info("Generating message to get MAC");

            string len = msg.Length.ToString("X4");

            String messageBlock = msg, commandCode = "C2", blockNo = "0", macKeyType = "3", macGenerationMode = "3", messageType = "0", key = macKey, messageLength = len;

            String message = commandCode;
            message += blockNo;
            message += macKeyType;
            message += macGenerationMode;
            message += messageType;
            message += key;
            message += messageLength;
            message += messageBlock;

            return SendMessage(message);
        }

        //390 Thales e-Security
        //Generate and Print a TMK, TPK or PVK
        //OE COMMAND

        //Import a key
        //A6 command
        public Dictionary<string, string> Import_ZPK_ZMK(string ZMK_LMK, string ZPK_ZMK)
        {
            Dictionary<String, String> responseZpkLmk = new Dictionary<string, string>();
            string response = ImportKey(ZMK_LMK, ZPK_ZMK);
            String errorCode = response.Substring(8, 2);

            responseZpkLmk.Add("Header", response.Substring(2, 4));

            responseZpkLmk.Add("ResponseCode", response.Substring(6, 2));

            responseZpkLmk.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                responseZpkLmk.Add("ZPK_LMK", response.Substring(10, 33));
                responseZpkLmk.Add("ZPK_CHK", response.Substring(43));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }

            //A7 00 U5F2DC42E10C92B16BA54802314CE95F5 AFDA4F
            return responseZpkLmk;
        }

        public string ImportKey(string zmkLmk, string zpkZmk)
        {
            //A6 001 UE68586760A163026C29710073AB2D7BE XAC4D3C5F603C1B502E5F45668A155C25 U00
            String message = "A6";
            message += "001";
            message += "U" + zmkLmk;
            message += "X" + zpkZmk;
            message += "U";           

            return SendMessage(message);
        }

    


        //generate a zmk for testing.
        //A0
        //Check the command Generate a Key (A0).
        // Mode = 0 (Generate key)
        //Key Type = 000(Zone Master Key, ZMK)

        public Dictionary<string, string> GenerateZMK_LMK()
        {
            
            return GenerateKeys("000");
        }

        public Dictionary<string, string> GenerateNewZPK_ZMK(string ZMK_LMK)
        {
            return GenerateKeysZPK_ZMK(ZMK_LMK);
        }
        public Dictionary<string, string> GenerateKeysZPK_ZMK(string ZMK_LMK)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = BuildCommandKeyZPK_ZMK(ZMK_LMK);
            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("ZPK_LMK", response.Substring(10, 33));
                Response.Add("ZPK_ZMK", response.Substring(43, 33));

                Response.Add("ZPK_CHK", response.Substring(76, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;
        }
        private string BuildCommandKeyZPK_ZMK(string ZMK_LMK)
        {
            logger.Info("Generating Command Key");
            String mode = "1", commandCode = "A0", keyType = "001", keyScheme = "U";

            String message = commandCode;
            message += mode;
            message += keyType;
            message += keyScheme;
            message += ";0";
            message += "U" + ZMK_LMK;
            message += "U";

            return SendMessage(message);
        }

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
                Response.Add("KEY", response.Substring(10, 33));

                Response.Add("KEY_CHK", response.Substring(43, 6));
            }
            else
            {
                //error?
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

        private string PrintTMK_Mailer(string deployer, string site, string terminalID, string componentNo)
        {
            logger.Info("Generating Command Key");
            String commandCode = "NE", _deployer = deployer, _site = site, _terminalID = terminalID;

            String message = commandCode;
            message += "002"; //TMK
        
            message += "U"; //Key Scheme         
            message += _deployer + ";"; //Field 0 
            message += _site + ";"; //Field 1
            message += _terminalID + ";"; //Field 2
            message += componentNo ; //Field 3

            return SendMessage(message);
        }

        private string GenerateandPrintaComponent(string deployer, string site, string terminalID, string componentNo)
        {
            logger.Info("Generating Command Key");
            String commandCode = "A2", _deployer = deployer, _site = site, _terminalID = terminalID;

            String message = commandCode;
            message += "002"; //TMK
            message += "2"; //chekc Value
            message += "U"; //Key Scheme
            message += _deployer + ";"; //Field 0 
            message += _site + ";"; //Field 1
            message += _terminalID + ";"; //Field 2
            message += componentNo; //Field 3

            return SendMessage(message);
        }

        private string GenerateandPrintTMKTAK(string deployer, string site, string terminalID, string componentNo)
        {
            logger.Info("Generating Command Key");
            String commandCode = "OE", _deployer = deployer, _site = site, _terminalID = terminalID;

            String message = commandCode;
            message += _deployer + ";"; //Field 0 
            message += _site + ";"; //Field 1
            message += _terminalID + ";"; //Field 2
            message += componentNo; //Field 3

            return SendMessage(message);
        }

        private string PrintTMK_LMK(string TMK_LMK, string deployer, string site, string terminalID)
        {
            logger.Info("Generating Command Key");
            String commandCode = "TA", _deployer = deployer, _site = site, _terminalID = terminalID;

            String message = commandCode;
            message += TMK_LMK;     
            message += _deployer + ";"; //Field 0 
            message += _site + ";"; //Field 1
            message += _terminalID; //Field 2

            return SendMessage(message);
        }

        private string FormKeys(string TMK1, string TMK2)
        {
            logger.Info("Generating Command Key");
            String commandCode = "A4";

            String message = commandCode;
            message += "2";
            message += "002";
            message += "U"; 
            message += TMK1 + ""; //TMK1
            message += TMK2; //TMK2 2

            return SendMessage(message);
        }
        
        //FormKeyfromEncryptedComponents
        public Dictionary<string, string> FormKeyfromEncryptedComponents(string TMK_LMK_1, string TMK_LMK_2)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = FormKeys(TMK_LMK_1, TMK_LMK_2);

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("TMK_LMK", response.Substring(10, 33));

                Response.Add("TMK_CHK", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;

        }
        public Dictionary<string, string> GenerateAndPrintaKeyasSplitComponents(string deployer, string site, string terminalID, string componentNo)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = PrintTMK_Mailer(deployer, site, terminalID, componentNo);

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("TMK_LMK", response.Substring(10, 33));

                Response.Add("TMK_CHK", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;

        }

        public Dictionary<string, string> GenerateAndPrintaKeyTMK(string deployer, string site, string terminalID, string componentNo)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = GenerateandPrintTMKTAK(deployer, site, terminalID, componentNo);

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("TMK_LMK", response.Substring(10, 33));
                
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;

        }

        public Dictionary<string, string> GenerateRandomPrintaKeyasSplitComponents(string deployer, string site, string terminalID, string componentNo)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = GenerateandPrintaComponent(deployer, site, terminalID, componentNo);

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                Response.Add("TMK_LMK", response.Substring(10, 33));

                Response.Add("TMK_CHK", response.Substring(43, 6));
            }
            else
            {
                logger.Error("ERROR CODE: " + errorCode);
            }
            return Response;

        }


        public Dictionary<string, string> PrintTMK(string TMK_LMK, string deployer, string site, string terminalID)
        {
            Dictionary<String, String> Response = new Dictionary<string, string>();
            String response = PrintTMK_LMK(TMK_LMK, deployer, site, terminalID);

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

        
            return Response;
        }
        //UBD06C80F567461F4EF1017CE5E9A1BE1

        public bool LoadPrintMailerFormatting(string formatting)
        {
            logger.Info("Generating Command Key");
            String commandCode = "PA", _formatting = formatting;

            String message = commandCode;
            message += _formatting;

            string response = SendMessage(message);

            Dictionary<String, String> Response = new Dictionary<string, string>();

            String errorCode = response.Substring(8, 2);

            Response.Add("Header", response.Substring(2, 4));

            Response.Add("ResponseCode", response.Substring(6, 2));

            Response.Add("ErrorCode", errorCode);
            logger.Debug("ErrorCode: " + errorCode);

            if (errorCode == "00")
            {
                return true;
            }

            return false;
        }

    }
}
