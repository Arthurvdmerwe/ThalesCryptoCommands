using System;
using System.Collections.Generic;
using SwitchLink.Core.Services.Services;

namespace SwitchLink.Cryptography.Interfaces
{
    public class PostBridgeCryptography : ICryptographyProvider
    {
        private readonly TritonCryptography.TritonCryptography triton_crypto;
        private readonly HostCryptography.HostCryptography host_crypto;
        private readonly ISessionsHostService _sessionsHostSvc = new SessionsHostService();
        private readonly ISessionsTritonService _sessionsTritonSvc = new SessionsTritonService();
        public PostBridgeCryptography()
        {
            triton_crypto = new TritonCryptography.TritonCryptography();
            host_crypto = new HostCryptography.HostCryptography();
        }

        public string TranslatePIN_TDES(string terminalPinKey, string pinEncryptionKey, string pinBlock, string accountNumber)
        {
            Dictionary<String, String> DestinationPin = triton_crypto.TranslatePIN_TPK_ZMK(terminalPinKey, pinEncryptionKey,
                pinBlock, accountNumber);
            if (DestinationPin["ErrorCode"] == "00")
            {
                return DestinationPin["DestPIN"];
            }
            return "Error: " + DestinationPin["ErrorCode"];
        }

        public string GenerateTerminalSessionKeys(string terminalMasterKey,string terminalId)
        {
            Dictionary<String, String> SessionKeys = triton_crypto.GenerateTerminalSessionKeys(terminalMasterKey);
  
            if (SessionKeys["ErrorCode"] == "00")
            {
                _sessionsTritonSvc.UpdateSessionKeysByTerminalId(terminalId, SessionKeys["TPK_TMK"], SessionKeys["TPK_CHK"], SessionKeys["TPK_LMK"]);
            }

            return SessionKeys["TPK_TMK"];
        }

        /// <summary>
        /// When the host has generated a 0810 key exchange response, we need to import the key under the LMK so we can translate future pins.
        /// </summary>
        /// <param name="HostPinKey"></param>
        /// <param name="CheckValue"></param>
        /// <param name="HostId"></param>
        /// <returns></returns>
        public bool ImportHostPinKey(string HostPinKeyandCheck)
        {
            string ZMK_LMK = _sessionsHostSvc.GetZMK_LMK;
            string HostPinKey = HostPinKeyandCheck.Substring(0, 32);
            Dictionary<string, string> result = host_crypto.Import_ZPK_ZMK(ZMK_LMK, HostPinKey);
            if (result["ErrorCode"] == "00")
            {
                _sessionsHostSvc.UpdateZPK_LMK(result["ZPK_LMK"], result["ZPK_CHK"]);
                return true;
            }
            return false;

        }

        public string GenerateHostPinKey()
        {
            string output = "";
            string ZMK_LMK = _sessionsHostSvc.GetZMK_LMK;
   
            Dictionary<string, string> result = host_crypto.GenerateNewZPK_ZMK(ZMK_LMK);
            if (result["ErrorCode"] == "00")
            {
                output += result["ZPK_ZMK"].Substring(1);
                output += result["ZPK_CHK"];
            }
            return output;

        }
    }
}
