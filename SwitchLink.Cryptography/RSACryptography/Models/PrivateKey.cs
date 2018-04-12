using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SwitchLink.Utils;

namespace SwitchLink.Cryptography.RSACryptography.Models
{
    public class PrivateKey
    {

        private byte[] _certDataWithLength;
        private byte[] _certDataWithoutLength;

        public PrivateKey(byte[] certDataWithLength)
        {
            this._certDataWithLength = certDataWithLength;
            _certDataWithoutLength = new byte[certDataWithLength.Length - 4];
            Array.Copy(certDataWithLength, 4, _certDataWithoutLength, 0, certDataWithLength.Length-4);
        }

        public byte[] GetPrivateKeyWithoutLengthBytes()
        {
            return _certDataWithoutLength;
        }

        public byte[] GetPrivateKeyWithLengtBytes()
        {
            return _certDataWithLength;
        }

        public string GetPrivateKeyWithLengthString()
        {
            return HexByteUtils.ByteArrayToHex(_certDataWithLength);
        }

        public string GetPrivateKeyWithoutLengthString()
        {
            return  HexByteUtils.ByteArrayToHex(_certDataWithoutLength); ;
        }

        public int GetPrivateKeyLength()
        {
            return 1;
        }
    }
}
