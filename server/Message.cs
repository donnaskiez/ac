using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using server;
using service;

namespace server
{
    public class Message
    {
        private byte[] _buffer;
        private int _bufferSize;
        private int _messageType;
        private ILogger _logger;
        private PACKET_HEADER _header;

        private enum MESSAGE_TYPE
        {
            MESSAGE_TYPE_REPORT = 1,
            MESSAGE_TYPE_SEND = 2,
            MESSAGE_TYPE_RECEIVE = 3
        }

        public struct PACKET_HEADER
        {
            public int message_type;
            public Int64 steam64_id;
        };

        struct REPORT_PACKET_HEADER
        {
            public int reportId;
        }

        public Message(byte[] buffer, int bufferSize, ILogger logger)
        {
            _buffer = buffer;
            _bufferSize = bufferSize;
            _logger = logger;
            _header = this.GetMessageHeader();

            _logger.Information("SteamID: {0}, Message type: {1}", 
                _header.steam64_id,
                _header.message_type
            );

            switch (_messageType)
            {
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_REPORT:
                    int reportId = GetReportType().reportId;
                    this.HandleReportMessage(reportId);
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

        unsafe private REPORT_PACKET_HEADER GetReportType()
        {
            return Helper.BytesToStructure<REPORT_PACKET_HEADER>(ref _buffer, sizeof(REPORT_PACKET_HEADER));
        }

        unsafe private void HandleReportMessage(int reportId)
        {
            _logger.Information("Report id: {0}", reportId);

            var openHandleFailure = Helper.BytesToStructure<Types.Reports.OPEN_HANDLE_FAILURE_REPORT>(ref _buffer, sizeof(PACKET_HEADER));

            _logger.Information("Report code: {0}, Process Name: {4} ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                openHandleFailure.ReportCode,
                openHandleFailure.ProcessId,
                openHandleFailure.ThreadId,
                openHandleFailure.DesiredAccess);

        }
    }
}
