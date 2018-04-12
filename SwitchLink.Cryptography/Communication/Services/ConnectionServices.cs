using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Hik.Communication.Scs.Client;
using Hik.Communication.Scs.Communication.EndPoints.Tcp;
using Hik.Communication.Scs.Communication.Messages;
using log4net;
using SwitchLink.Cryptography.Communication.Messages;
using SwitchLink.Cryptography.Communication.Protocols;

namespace SwitchLink.Cryptography.Communication.Services
{
    public class ConnectionServices : IDisposable
    {
        private readonly ILog _log = LogManager.GetLogger("HSMConnectionLogger");
        private readonly IScsClient _tcpClient;
        private TaskCompletionSource<byte[]> _tcsHsm;
        
        public ConnectionServices(string ip, int port)
        {
            _tcpClient = ScsClientFactory.CreateClient(new ScsTcpEndPoint(ip, port));
            _tcpClient.WireProtocol = new HsmProtocol();

            _tcpClient.MessageReceived -= OnMessageReceived;

            _tcpClient.MessageReceived += OnMessageReceived;
            _tcpClient.Connect();
        }

        internal string SendCommand(string message)
        {
            _log.Info("Message to be sent to the HSM : ");
            byte[] msg = Encoding.UTF8.GetBytes("HEAD" + message);
            byte[] len = BitConverter.GetBytes((short)msg.Length);
            byte[] constMsg = len.Reverse().Concat(msg).ToArray();

            byte[] response = Send(constMsg).Result;
            string result = Encoding.ASCII.GetString(response);

            return result;
        }

        internal byte[] SendCommandBytes(string message)
        {
            _log.Info("Message to be sent to the HSM : ");
            byte[] msg = Encoding.UTF8.GetBytes("HEAD" + message);
            byte[] len = BitConverter.GetBytes((short)msg.Length);
            byte[] constMsg = len.Reverse().Concat(msg).ToArray();

            byte[] response = Send(constMsg).Result;
      
            return response;
        }

        internal byte[] SendBytes(byte[] message)
        {
            _log.Info("Message to be sent to the HSM : ");
            byte[] msg = Encoding.UTF8.GetBytes("HEAD");
            msg = msg.Concat(message).ToArray();
            byte[] len = BitConverter.GetBytes((short)msg.Length);
            byte[] constMsg = len.Reverse().Concat(msg).ToArray();

            byte[] response = Send(constMsg).Result;

            return response;
        }

        private Task<byte[]> Send(byte[] message)
        {
            _tcsHsm = new TaskCompletionSource<byte[]>();
            _tcpClient.SendMessage(new HsmRawMessage(message));

            return _tcsHsm.Task;
        }
        
        private void OnMessageReceived(object sender, MessageEventArgs e)
        {
            var response = e.Message as HsmRawMessage;
            if (response != null)
            {
                _tcsHsm.SetResult(response.RawBytes);
              
            }
            else
                _tcsHsm.SetException(new InvalidDataException("NULL responsed from HSM"));
        }

        public void Dispose()
        {
            _tcpClient.Disconnect();
            _tcpClient.Dispose();
        }
    }
}
