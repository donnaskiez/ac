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

        private enum MESSAGE_TYPE
        {
            MESSAGE_TYPE_REPORT = 1,
            MESSAGE_TYPE_SEND = 2,
            MESSAGE_TYPE_RECEIVE = 3
        }

        struct PACKET_HEADER
        {
            int messageType;
        }

        struct REPORT_PACKET_HEADER
        {
            int reportId;
        }

        public Message(byte[] buffer, int bufferSize, ILogger logger)
        {
            _buffer = buffer;
            _bufferSize = bufferSize;
            _logger = logger;

            this.GetMessageType();

            _logger.Information("Message type: {0}", _messageType);

            switch (_messageType)
            {
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_REPORT:
                    this.HandleReportMessage(this.GetReportType());
                    break;
                default:
                    _logger.Information("This message type is not accepted at the moment.");
                    break;
            }
        }

        private void GetMessageType()
        {
            _messageType = BitConverter.ToInt32(_buffer, 0);
        }

        private int GetReportType()
        {
            return BitConverter.ToInt32(_buffer, sizeof(int));
        }

        private void HandleReportMessage(int reportId)
        {
            _logger.Information("Report id: {0}", reportId);

            var openHandleFailure = Helper.BytesToStructure<Types.Reports.OPEN_HANDLE_FAILURE_REPORT>(ref _buffer, sizeof(int));

            _logger.Information("Report code: {0}, Process Name: {4} ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                openHandleFailure.ReportCode,
                openHandleFailure.ProcessId,
                openHandleFailure.ThreadId,
                openHandleFailure.DesiredAccess);

        }
    }
}
