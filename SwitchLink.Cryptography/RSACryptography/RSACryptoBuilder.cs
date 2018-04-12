using System;
using System.Linq;
using System.Text;
using log4net;
using SwitchLink.Utils;


namespace SwitchLink.Cryptography.RSACryptography
{
    public class RSACryptoBuilder: BaseCryptography
    {
        public string BuildDecryptPinPadPublicKeyResponse(byte[] mac, byte[] manufacturerPublicKey,byte[] signedPinPadPublicKey, string PublicKeyEncoding="01")
        {
            String message = "HO";
            message += PublicKeyEncoding;
            message += mac;
            message += manufacturerPublicKey;
            message += signedPinPadPublicKey.Length;
            message += signedPinPadPublicKey;
            
            return SendMessage(message);

           
        }

        public string BuildPublicKeyVerificationCode(byte[] publicKeyWithEncoding, string publicKeyEncoding="02")
        {
            ASCIIEncoding ascii = new ASCIIEncoding();
            byte[] message = Encoding.UTF8.GetBytes("H2"+ publicKeyEncoding);
            message = message.Concat(publicKeyWithEncoding).ToArray();
         
            byte[] returnData =  SendBytes(message);
            return ascii.GetString(returnData);
      

        }

        /*
                H8/H9 Command

        Input Data:

        001-H801<FDC694A6>
        <30550250AB378F98E373BBC6FA5E698F4F095A6D693A851E53C35CC9633947399C09D70932776DBEA5F2F0F0C4DAB4693CACB4D07B19242FF0435C55E3D4E28EFD563457F7EBA31BE1123DEA78CEC1573716130B020103>
        ;99
         0192
        <99658789F42672E7C51CB6ECAF3F061BBABCD954D4113E1CD9BD7BD4DF1BD94E6CBC10F497E9AE68265E87F77BFF293AA2D9FDE9C1A8F12A04D9B4D8DB9F5EAEE4690883838DEF670174E70C79E674F97E2457DD85EEEB346A17DD1F39CB3E8B2D69949436051994F8687F0FEE6558F28180D5A63946CD60604B1C82F6AE14454F5824CBFDCEE07478D2F0239299B64CD900DFF7559423E98F0C7AB8229933E4DD5A5E0BD736F8172668676949493577E323FC8EC592437F6DF20EDB5FBB6E92>
        ;0080
        <7C9DDD3AEFF1D50BAFD11DBAF240BE827BAA156F9E8BB555CC019E183B3708F26EBE6C94702A9AD7CC1D2159CF587437532969D113C70BD622EB81AFC06E9408F1B69F3ED838A9EADFB41FB0E6E4202E>
        ;1234567890123456;000


        Input data converted to binary

        <3030312D48383031FDC694A630550250AB378F98E373BBC6FA5E698F4F095A6D693A851E53C35CC9633947399C09D70932776DBEA5F2F0F0C4DAB4693CACB4D07B19242FF0435C55E3D4E28EFD563457F7EBA31BE1123DEA78CEC1573716130B0201033B39393031393299658789F42672E7C51CB6ECAF3F061BBABCD954D4113E1CD9BD7BD4DF1BD94E6CBC10F497E9AE68265E87F77BFF293AA2D9FDE9C1A8F12A04D9B4D8DB9F5EAEE4690883838DEF670174E70C79E674F97E2457DD85EEEB346A17DD1F39CB3E8B2D69949436051994F8687F0FEE6558F28180D5A63946CD60604B1C82F6AE14454F5824CBFDCEE07478D2F0239299B64CD900DFF7559423E98F0C7AB8229933E4DD5A5E0BD736F8172668676949493577E323FC8EC592437F6DF20EDB5FBB6E923B303038307C9DDD3AEFF1D50BAFD11DBAF240BE827BAA156F9E8BB555CC019E183B3708F26EBE6C94702A9AD7CC1D2159CF587437532969D113C70BD622EB81AFC06E9408F1B69F3ED838A9EADFB41FB0E6E4202E3B313233343536373839303132333435363B303030>


        Response:

        001-H900
        H604A678C8C78E1B9CFD415220D418E76
        U9912C5D8B113B5E9D6787D57EE9E43BA
        1122334455
        9876543210987654 
        */

        public byte[] BuildCrossAcquirerKeyEncryptionKeyunderInitialTransportKey(string publicKeyEncoding, byte[] macPublicKey, byte[] pinPadPublicKey, byte[] secretKey, byte[] dataBlock, string randomNumber)
        {

            String message = "H8"; //ascii
            message += publicKeyEncoding;//ascii

            byte[] bytes1 = Encoding.ASCII.GetBytes(message);
            message += macPublicKey;//binary
            message += pinPadPublicKey;//binary

            byte[] byte2 = macPublicKey.Concat(pinPadPublicKey).ToArray();

            string message2 = ";99";//ascii
            message2 += secretKey.Length.ToString("D4");//ascii
            byte[] byte3 = Encoding.ASCII.GetBytes(message2);

            byte[] byte4 =  secretKey;//binary

            string message4 = ";"; //ascii
            message4 += dataBlock.Length.ToString("D4");//ascii
            byte[] byte5 = Encoding.ASCII.GetBytes(message4);

            byte[] byte6 = dataBlock;//binary

            byte[] byte7  = Encoding.ASCII.GetBytes(";");//ascii

            int discarded;
            byte[] byte8 = HexByteUtils.GetBytes(randomNumber, out discarded);//binary

            message += ";000";//ascii
            byte[] byte9 = Encoding.ASCII.GetBytes(";000");

            byte[] dataBytes =
                bytes1.Concat(byte2)
                    .Concat(byte3)
                    .Concat(byte4)
                    .Concat(byte5)
                    .Concat(byte6)
                    .Concat(byte7)
                    .Concat(byte8)
                    .Concat(byte9)
                    .ToArray();
            return SendBytes(dataBytes);
           
        }

        public string BuildInitialTerminalMasterKeys(string acquirerInitilisationKey)
        {
            String message = "CO";
            message += acquirerInitilisationKey;

            return SendMessage(message);

        }

        public string BuildAnAcquirerMasterKeyEncryptingKey(string crossAcqiuirerKeyEncryptingKey, string acquirerInstitutionIdentificationCode)
        {
            String message = "C8";
            message += crossAcqiuirerKeyEncryptingKey;
            message += "1";
            message += acquirerInstitutionIdentificationCode;
            return SendMessage(message);
        }

        public string BuildRandomNumber()
        {
            String message = "C6";
       
            return SendMessage(message);
        }

        public string BuildPinPadAcquirerSecurityNumber(string acquirerInitilisationKey)
        {
            String message = "PK";
            message += acquirerInitilisationKey;
            return SendMessage(message);
        }

        /*
           MAC using C2 command (AS2805) with ZAKs

            001-C2 03 31 UACD981966EBEEB603ECE9AED02CD4070000A01234567899876543210
            001-C300C6D75325

            MAC = C6D75325

            +++++++++++++++++++++++++++++++++++++++++++++++++++++++
            Verify MAC using C4 command (AS2805) with ZAKr

            002-C4 0321U0721CB7EF682E98F8B2D4E0C4E7E7C4AC6D75325000A01234567899876543210
            002-C500
             */
        public string BuildMacOnMessage(string macKey, byte[] data)
        {
            String message = "C2";
            return SendMessage(message);
        }

        /*

         Generate a MAC on 1024 RSA key

         002-EO01<308188028180A7A8F2655F4715035E0059CFAF223EC13214B17C3C8402B8EB23BBDD6F8F284E5618516812FADDDED7E129C318435DDF822813CC53269C516C7F3BDBE905FC3BAA4AC1C164A5D4B10A29E80FB5D48FAD1B430AA8DE0E08AA0C24700B6A84513CC67A9A284456C32B5196A6070707C99E114A42D385F31CE4D3A22926E366C07D0203010001>

         002-EP00<4D507DD1><308188028180A7A8F2655F4715035E0159CFAF223EC13214B17C3C8402B8EB23BBDD6F8F284E5618516812FADDDED7E129C318435DDF822813CC53269C516C7F3BDBE905FC3BAA4AC1C164A5D4B10A29E80FB5D48FAD1B430AA8DE0E08AA0C24700B6A84513CC67A9A284456C32B5196A6070707C99E114A42D385F31CE4D3A22926E366C07D0203010101>

        */

        public byte[] BuildMacOnRSACertificate(byte[] data)
        {
            
            String message = "EO01";
            byte[] messageData = Encoding.ASCII.GetBytes(message);
            byte[] dataSend = messageData.Concat(data).ToArray();
            return SendBytes(dataSend);
        }



        /*
         #
         # Create an MPK of 512 bits and exponent of 03
         HSM-EI 0 0512 01 0002 <HEX 03 HEX>

         EI 0 0512 01 0002 03
         # Create an MPK of 1024 bits and exponent of 65537
         HSM-EI 2 1024 01 0017 <HEX 010001 HEX>
         #
        

         Public Key
         30760270A7D52F75F03D5E1B7B5315E532EA5F71F7345F5DBC5D3D9EAB233335AEEF36BC320BE5C58D278E4E0533EE7BAE7B6A2785192FE81B91A41C60171DD4218F854F84F9B87D56177AF18477FC8E4F77A52A4D9391F372846B5EAEA179B05E69FCD49D3BA29487D14CE975FC783B61BCEC670202BA7F


         Private Key
         30323936BCBEA1C55C90B9917C561F81C8429688A53E7DE4847DFA56CB7737602EE5161892C9F843EDF7A19CEAB1402040E43BEDA10AF727AD45F66A65B6CCDC46427C983F4746B26DD93469AD1876416FADF2F91B475B4757E7DD24360AC79C863847FE405D710286B9E91686E02679DA4C35E0411346CABC69DBAF0FFD9AE37D597FB9D114748F6E71F9966131FC69DD8DF466E903237614517BB3C3C3FDB88A1D1DD18C5EDAEFA7800D1C49C1927DA3AF56B6FD7950F8308226F85434C1D0933B0FC22AC65665B93868128B6EC515B7FBDD1ED9814854849D21EA63F745BC1F3F94BFFAE3FE45B112A87BA886544427614100BECF6D622F740467FEA683309BDA4822FFB69C7679A5CA7D4C86F43C5094B1E427795B2D7D04E5351ABD6A814CB9857E6FB71CFFF1355D7A
         
            
        command_code = 'EI'
        #keyType: 2- Key and management, 0-signature only, 1-key management only, 3-icc key, 4-ssl
        KeyType = '2'
        KeyLength = '0896'
        PublicKeyEncoding = '01'
        #public_exponent_length = '0016'
        #public_exponent = HexToByte('BA7F')




        message = command_code
        message += KeyType
        message += KeyLength
        message += PublicKeyEncoding
        #message += public_exponent_length
        #message += public_exponent
          */
        public byte[] BuildRsaKeyPair(int keyLength, string publicExponent, string keyType="2", string publicKeyEncoding = "01")
        {
            String message = "EI";
            message += keyType;
            message += keyLength.ToString("D4");
            message += publicKeyEncoding;
            return SendMessageBytes(message);
        }
    }
}
