using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchLink.Cryptography.Interfaces
{
   public interface ICryptographyProvider
   {

       string TranslatePIN_TDES(string terminalPinKey, string pinEncryptionKey, string pinBlock, string accountNumber);
       string GenerateTerminalSessionKeys(string terminalMasterKey, string terminalId);
       bool ImportHostPinKey(string HostPinKey);
       string GenerateHostPinKey();

   }
}
