using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;
using Serilog;

namespace server
{
    public class Message
    {
        private byte[] _buffer;
        private int _bufferSize;
        private int _messageType;

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

        public Message(byte[] buffer, int bufferSize)
        {
            _buffer = buffer;
            _bufferSize = bufferSize;

            this.GetMessageType();

            switch (_messageType)
            {
                case (int)MESSAGE_TYPE.MESSAGE_TYPE_REPORT:
                    this.HandleReportMessage(this.GetReportType());
                    break;
                default:
                    Log.Logger.Information("This message type is not accepted at the moment.");
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
            Log.Logger.Information("Report id: {0}", reportId);
        }
    }
}
