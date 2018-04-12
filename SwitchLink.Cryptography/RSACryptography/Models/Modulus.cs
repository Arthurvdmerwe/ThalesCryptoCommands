using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SwitchLink.Utils;

namespace SwitchLink.Cryptography.RSACryptography.Models
{
    public class Modulus
    {
   

        private byte[] ModBytesData;
        private string ModStringData;
        private int ModInteger;
        private int discarded;

        public Modulus(string mod)
        {
            ModStringData = mod;
            ModBytesData = HexByteUtils.GetBytes(mod, out discarded);
        }

        public  Modulus(byte[] mod)
        {
            byte[] modulus = new byte[3];
            //more than 4 octets then it has  a length indicator
            if (mod.Length > 4)
            {
                Array.Copy(mod, 2, modulus, 0, 3);
                mod = modulus;
            }
            ModBytesData = mod;
            ModStringData = HexByteUtils.ByteArrayToHex(mod);
            ModInteger = int.Parse(ModStringData, NumberStyles.HexNumber);
        }

        public string getModulusString(int padding)
        {
            return ModStringData.PadLeft(
                padding, '0');
        }

        public int getModulusInteger()
        {
            return ModInteger; 
        }

        public byte[] getModulusBytes(int padding)
        {
            try
            {
                int discarded;

                return HexByteUtils.GetBytes(ModStringData.PadLeft(
                    padding, '0'), out discarded);
            }
            catch (System.IO.InvalidDataException e)
            {
                string p = e.Message;
                return new byte[0];
            }
        }

        public void setModulus(int modulus)
        {
            ModStringData = modulus.ToString("X2");
            ModBytesData = HexByteUtils.GetBytes(ModStringData, out discarded);
            ModInteger = int.Parse(ModStringData, NumberStyles.HexNumber);
        }
    }
}
