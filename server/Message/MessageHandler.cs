using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using System.Net;
using System.Net.Sockets;
using server.Types.ClientReport;
using server.Types.ClientSend;
using System.Runtime.InteropServices;
using server.Database.Model;
using server.Database.Entity;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Ocsp;

namespace server.Message
{
    public class MessageHandler
    {
        private byte[] _buffer;
        private int _bufferSize;
        private ILogger _logger;
        private PACKET_HEADER _header;
        private NetworkStream _networkStream;
        private TcpClient _tcpClient;

        private enum MESSAGE_TYPE
        {
            MESSAGE_TYPE_CLIENT_REPORT = 1,
            MESSAGE_TYPE_CLIENT_SEND = 2,
            MESSAGE_TYPE_CLIENT_REQUEST = 3
        }

        public struct PACKET_HEADER
        {
            public int message_type;
            public ulong steam64_id;
        };

        private struct PACKET_REQUEST_HEADER
        {
            public int RequestId;
        }

        public MessageHandler(TcpClient client, byte[] buffer, int bufferSize, ILogger logger)
        {
            _tcpClient = client;
            _networkStream = client.GetStream();
            _buffer = buffer;
            _bufferSize = bufferSize;
            _logger = logger;
            _header = GetMessageHeader();

            switch (_header.message_type)
            {
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_CLIENT_REPORT:
                    HandleClientSendReport();
                    break;
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_CLIENT_SEND:
                    HandleClientSendMessage();
                    break;
                default:
                    _logger.Information("This message type is not accepted at the moment.");
                    break;
            }
        }

        private void HandleClientSendReport()
        {
            ClientReport report = new ClientReport(_logger, _buffer, _bufferSize, _header);
           
            if (report.HandleMessage())
            {
                byte[] reponsePacket = report.GetResponsePacket();
                this.SendResponsePacketToClient(reponsePacket);
                return;
            }

            _logger.Warning("Failed to handle client sent report");
        }

        private void HandleClientSendMessage()
        {
            ClientSend send = new ClientSend(_logger, ref _buffer, _bufferSize, _header);

            if (send.HandleMessage())
            {
                byte[] responsePacket = send.GetResponsePacket();
                this.SendResponsePacketToClient(responsePacket);
                return;
            }

            _logger.Warning("Failed to handle client send message");
        }
        private PACKET_HEADER GetMessageHeader()
        {
            return Helper.BytesToStructure<PACKET_HEADER>(_buffer, 0);
        }

        private void SendResponsePacketToClient(byte[] responsePacket)
        {
            _networkStream.Write(responsePacket, 0, responsePacket.Length);
        }
    }
}
