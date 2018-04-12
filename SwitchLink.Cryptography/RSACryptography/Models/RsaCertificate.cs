using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SwitchLink.Cryptography.RSACryptography.Models
{
    public class RsaCertificate
    {

        private PublicKey publicKey;
        private PrivateKey privateKey;
      
    

        public RsaCertificate(byte[] PublicKey, byte[] PrivateKey)
        {
          
            publicKey = new PublicKey(PublicKey);
            privateKey = new PrivateKey(PrivateKey);
     
        }

        public PublicKey getPublicKey()
        {
            return this.publicKey;
        }

        public PrivateKey getPrivateKey()
        {
            return this.privateKey;
        }

        public Modulus getModulus()
        {
            return this.publicKey.GetModulus();
        }
    }
}
