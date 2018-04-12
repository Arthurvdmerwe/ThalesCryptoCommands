using Hik.Communication.Scs.Communication.Messages;

namespace SwitchLink.Cryptography.Communication.Messages
{
    public class HsmRawMessage : IScsMessage
    {
        public string MessageId { get; private set; }
        public string RepliedMessageId { get; set; }
        public byte[] RawBytes { get; private set; }

        public HsmRawMessage(byte[] rawBytes)
        {
            RawBytes = rawBytes;
        }
    }
}
