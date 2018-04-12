using Hik.Communication.Scs.Communication.Protocols;

namespace SwitchLink.Cryptography.Communication.Protocols
{
    class HsmProtocolFactory : IScsWireProtocolFactory
    {
        public IScsWireProtocol CreateWireProtocol()
        {
            return new HsmProtocol();
        }
    }
}
