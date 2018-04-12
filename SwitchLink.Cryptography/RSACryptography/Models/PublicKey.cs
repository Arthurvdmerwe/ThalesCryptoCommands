using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SwitchLink.Utils;

namespace SwitchLink.Cryptography.RSACryptography.Models
{
    public class PublicKey
    {
        private byte[] keyBytesData;
        private string keyStringData;
        private Modulus mod;
        private byte[] HSMPublicKey;

        public PublicKey(byte[] certData)
        {


            HSMPublicKey = certData;
            //HSMPublicKey = new byte[certData.Length - 2];
            //Array.Copy(certData, 2, HSMPublicKey, 0, certData.Length-2);
            //public certificate
            Asn1.Asn1Reader reader = new Asn1.Asn1Reader(certData);
            reader.MoveNext();
            byte[] FirstDataSeq =  reader.GetPayload();

            string FirstDataSeqHex = HexByteUtils.ByteArrayToHex(FirstDataSeq);
            keyBytesData = FirstDataSeq;
            keyStringData = FirstDataSeqHex;

            //public modulus
            reader.MoveNext();
            byte[] SecondDataSeq = reader.GetTagRawData();
            string SecondDataSeqHex = HexByteUtils.ByteArrayToHex(SecondDataSeq);
            byte[] modulus = new byte[3];
            Array.Copy(SecondDataSeq, 2, modulus, 0, 3);


            //create modulus object
            mod = new Modulus(modulus);
        }

        public byte[] GetKeyBinaryData()
        {
            return keyBytesData;
        }

        public string GetKeyHexData()
        {
            return keyStringData;
        }


        public Modulus GetModulus()
        {
            return mod;
        }

        public byte[] getHSMPublicKey()
        {
            return HSMPublicKey;
        }


        public string getHSMPublicKeyString()
        {
            return HexByteUtils.ByteArrayToHex(HSMPublicKey);
        }


    }
}
