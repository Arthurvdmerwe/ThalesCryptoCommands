using System;
using SwitchLink.Cryptography.Communication.Services;
using System.Configuration;
using Common.Logging;

namespace SwitchLink.Cryptography
{
    public abstract class BaseCryptography
    {
        private readonly string HsmIp = ConfigurationManager.AppSettings["app:HSM IP"];
        private readonly int HsmPort = int.Parse(ConfigurationManager.AppSettings["app:HSM Port"]);
        private readonly ILog logger = LogManager.GetLogger<BaseCryptography>();

        protected string SendMessage(string message)
        {
            try
            {
                using (var svr = new ConnectionServices(HsmIp, HsmPort))
                {
                    string hsmResponse = svr.SendCommand(message);
                    return hsmResponse;
                }
            }
            catch (TimeoutException e)
            {
                logger.Error(e.ToString());
                throw;
            }
        }

        protected byte[] SendMessageBytes(string message)
        {
            try
            {
                using (var svr = new ConnectionServices(HsmIp, HsmPort))
                {
                    byte[] hsmResponse = svr.SendCommandBytes(message);
                    return hsmResponse;
                }
            }
            catch (TimeoutException e)
            {
                logger.Error(e.ToString());
                throw;
            }
        }

        protected byte[] SendBytes(byte[] message)
        {
            try
            {
                using (var svr = new ConnectionServices(HsmIp, HsmPort))
                {
                    byte[] hsmResponse = svr.SendBytes(message);
                    return hsmResponse;
                }
            }
            catch (TimeoutException e)
            {
                logger.Error(e.ToString());
                throw;
            }
        }
    }
}
