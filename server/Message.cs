using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using server;
using System.Net;
using System.Net.Sockets;
using server.Types.ClientReport;
using server.Types.ClientSend;
using System.Runtime.InteropServices;

namespace server
{
    public class Message
    {
        private byte[] _buffer;
        private int _bufferSize;
        private ILogger _logger;
        private PACKET_HEADER _header;
        private NetworkStream _networkStream;

        private enum MESSAGE_TYPE
        {
            MESSAGE_TYPE_CLIENT_REPORT = 1,
            MESSAGE_TYPE_CLIENT_SEND = 2,
            MESSAGE_TYPE_CLIENT_REQUEST = 3
        }

        private enum CLIENT_SEND_REQUEST_ID
        {
            SYSTEM_INFORMATION = 10
        }

        public struct PACKET_HEADER
        {
            public int message_type;
            public Int64 steam64_id;
        };

        struct PACKET_REQUEST_HEADER
        {
            public int RequestId;
        }

        public Message(NetworkStream networkStream, byte[] buffer, int bufferSize, ILogger logger)
        {
            _networkStream = networkStream;
            _buffer = buffer;
            _bufferSize = bufferSize;
            _logger = logger;
            _header = this.GetMessageHeader();

            switch (_header.message_type)
            {
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_CLIENT_REPORT:
                    int reportId = GetPacketRequestId().RequestId;
                    this.HandleReportMessage(reportId);
                    break;
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_CLIENT_SEND:
                    int requestId = GetPacketRequestId().RequestId;
                    this.HandleClientSendMessage(requestId);
                    break;
                default:
                    _logger.Information("This message type is not accepted at the moment.");
                    break;
            }
        }
        
        private PACKET_HEADER GetMessageHeader()
        {
            return Helper.BytesToStructure<PACKET_HEADER>(ref _buffer, 0);
        }

        unsafe private PACKET_REQUEST_HEADER GetPacketRequestId()
        {
            return Helper.BytesToStructure<PACKET_REQUEST_HEADER>(ref _buffer, sizeof(PACKET_HEADER));
        }

        unsafe private CLIENT_SEND_PACKET_HEADER GetClientSendPacketHeader()
        {
            return Helper.BytesToStructure<CLIENT_SEND_PACKET_HEADER>(ref _buffer, sizeof(PACKET_HEADER));
        }

        unsafe private void HandleReportMessage(int reportId)
        { 
            OPEN_HANDLE_FAILURE_REPORT openHandleFailure = 
                Helper.BytesToStructure<OPEN_HANDLE_FAILURE_REPORT>(ref _buffer, sizeof(PACKET_HEADER));

            _logger.Information("Report code: {0}, ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                openHandleFailure.ReportCode,
                openHandleFailure.ProcessId,
                openHandleFailure.ThreadId,
                openHandleFailure.DesiredAccess);
        }

        private void HandleClientSendMessage(int clientSendId)
        {
            CLIENT_SEND_PACKET_HEADER header = GetClientSendPacketHeader();

            switch (header.RequestId)
            {
                case (int)CLIENT_SEND_REQUEST_ID.SYSTEM_INFORMATION:
                    this.HandleClientSendHardwareInformation(header);
                    break;
            }

        }

        unsafe private void HandleClientSendHardwareInformation(CLIENT_SEND_PACKET_HEADER sendPacketHeader)
        {
            _logger.Information("Handling client send hardware information");

            string moboSerial = Helper.FixedUnsafeBufferToSafeString(
                ref _buffer, _bufferSize, sizeof(PACKET_HEADER) + sizeof(CLIENT_SEND_PACKET_HEADER), 32);

            if (moboSerial == null)
                return;

            string driveSerial = Helper.FixedUnsafeBufferToSafeString(
                ref _buffer, _bufferSize, sizeof(PACKET_HEADER) + sizeof(CLIENT_SEND_PACKET_HEADER) + 32, 32);

            if (driveSerial == null)
                return;

            _logger.Information("SteamId: {0}, Mobo Serial: {1}, drive serial: {2}", _header.steam64_id, moboSerial, driveSerial);


        }
    }
}
 