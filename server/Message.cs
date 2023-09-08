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
using System.Net;
using System.Net.Sockets;
using server.Types.Reports;
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
            MESSAGE_TYPE_REPORT = 1,
            MESSAGE_TYPE_SEND = 2,
            MESSAGE_TYPE_RECEIVE = 3
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PACKET_HEADER
        {
            public int message_type;
            public Int64 steam64_id;
            public fixed char motherboard_serial_number[32];
            public fixed char device_drive_0_serial[32];
        };

        struct REPORT_PACKET_HEADER
        {
            public int reportId;
        }

        public Message(NetworkStream networkStream, byte[] buffer, int bufferSize, ILogger logger)
        {
            _networkStream = networkStream;
            _buffer = buffer;
            _bufferSize = bufferSize;
            _logger = logger;
            _header = this.GetMessageHeader();

            char[] string_1 = new char[32];
            char[] string_2 = new char[32];

            unsafe
            {
                for (int i = 0; i < 32; i++)
                {
                    string_1[i] = (char)_buffer[16+i];
                }

                for (int i=0;i<32;i++)
                {
                    string_2[i] = (char)_buffer[16 + 32 + i];
                }
            }

            string test1 = new string(string_1);
            string test2 = new string(string_2);

            _logger.Information("SteamID: {0:x}, MoboSerial: {2:x}, DriveSerial: {3:x}, Message type: {1:x}",
                _header.steam64_id,
                _header.message_type,
                string_1,
                string_2
            );


            switch (_header.message_type)
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
            return Helper.BytesToStructure<REPORT_PACKET_HEADER>(ref _buffer, 80);
        }

        unsafe private void HandleReportMessage(int reportId)
        {
            _logger.Information("Report id: {0}", reportId);

            OPEN_HANDLE_FAILURE_REPORT openHandleFailure = 
                Helper.BytesToStructure<Types.Reports.OPEN_HANDLE_FAILURE_REPORT>(ref _buffer, 80);

            _logger.Information("Report code: {0}, ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                openHandleFailure.ReportCode,
                openHandleFailure.ProcessId,
                openHandleFailure.ThreadId,
                openHandleFailure.DesiredAccess);

        }
    }
}
