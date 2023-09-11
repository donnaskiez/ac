using Serilog;
using server.Database.Entity;
using server.Database.Entity.Report;
using server.Database.Model;
using server.Types.ClientReport;
using System;
using System.Collections.Generic;
using System.Drawing.Printing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static server.Message.MessageHandler;

namespace server.Message
{
    public class ClientReport : IClientMessage
    {
        private readonly ILogger _logger;
        private byte[] _buffer;
        private int _bufferSize;
        private PACKET_HEADER _packetHeader;
        private CLIENT_REPORT_PACKET_HEADER _clientReportPacketHeader;
        private CLIENT_REPORT_PACKET_RESPONSE _responsePacket;

        private enum CLIENT_SEND_REPORT_ID
        {
            REPORT_CODE_MODULE_VERIFICATION = 10,
            REPORT_CODE_START_ADDRESS_VERIFICATION = 20,
            REPORT_PAGE_PROTECTION_VERIFICATION = 30,
            REPORT_PATTERN_SCAN_FAILURE = 40,
            REPORT_NMI_CALLBACK_FAILURE = 50,
            REPORT_MODULE_VALIDATION_FAILURE = 60,
            REPORT_ILLEGAL_HANDLE_OPERATION = 70,
            REPORT_INVALID_PROCESS_ALLOCATION = 80,
            REPORT_HIDDEN_SYSTEM_THREAD = 90,
            REPORT_ILLEGAL_ATTACH_PROCESS = 100
        }

        private struct CLIENT_REPORT_PACKET_HEADER
        {
            public int reportCode;
        }

        private struct CLIENT_REPORT_PACKET_RESPONSE
        {
            public int success;
        }

        public ClientReport(ILogger logger, ref byte[] buffer, int bufferSize, PACKET_HEADER packetHeader)
        {
            this._logger = logger;
            this._buffer = buffer;
            this._bufferSize = bufferSize;
            this._packetHeader = packetHeader;
            this._responsePacket = new CLIENT_REPORT_PACKET_RESPONSE();
            this.GetPacketHeader();
        }

        unsafe public void GetPacketHeader()
        {
            this._clientReportPacketHeader = 
                Helper.BytesToStructure<CLIENT_REPORT_PACKET_HEADER>(_buffer, sizeof(PACKET_HEADER));
        }

        public byte[] GetResponsePacket()
        {
            return Helper.StructureToBytes<CLIENT_REPORT_PACKET_RESPONSE>(ref this._responsePacket);
        }

        private void SetResponsePacketData(int success)
        {
            this._responsePacket.success = success;
        }

        public bool HandleMessage()
        {
            if (this._clientReportPacketHeader.reportCode == 0)
            {
                _logger.Error("Failed to get the report packet code");
                return false;
            }

            switch (this._clientReportPacketHeader.reportCode)
            {
                case (int)CLIENT_SEND_REPORT_ID.REPORT_CODE_MODULE_VERIFICATION:
                    _logger.Information("REPORT_CODE_MODULE_VERIFICATION");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_CODE_START_ADDRESS_VERIFICATION:
                    _logger.Information("REPORT_CODE_START_ADDRESS_VERIFICATION");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_PAGE_PROTECTION_VERIFICATION:
                    _logger.Information("REPORT_PAGE_PROTECTION_VERIFICATION");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_PATTERN_SCAN_FAILURE:
                    _logger.Information("REPORT_PATTERN_SCAN_FAILURE");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_NMI_CALLBACK_FAILURE:
                    _logger.Information("REPORT_NMI_CALLBACK_FAILURE");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_MODULE_VALIDATION_FAILURE:
                    _logger.Information("REPORT_MODULE_VALIDATION_FAILURE");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_ILLEGAL_HANDLE_OPERATION:
                    _logger.Information("REPORT_ILLEGAL_HANDLE_OPERATION");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_INVALID_PROCESS_ALLOCATION:
                    _logger.Information("REPORT_INVALID_PROCESS_ALLOCATION");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_HIDDEN_SYSTEM_THREAD:
                    _logger.Information("REPORT_HIDDEN_SYSTEM_THREAD");
                    break;
                case (int)CLIENT_SEND_REPORT_ID.REPORT_ILLEGAL_ATTACH_PROCESS:
                    _logger.Information("REPORT_ILLEGAL_ATTACH_PROCESS");
                    break;
                default:
                    _logger.Information("Report code not handled yet");
                    break;
            }

            SetResponsePacketData(1);
            return true;
        }

        unsafe public void HandleReportIllegalHandleOperation()
        {
            OPEN_HANDLE_FAILURE_REPORT report = Helper.BytesToStructure<OPEN_HANDLE_FAILURE_REPORT>(_buffer, sizeof(PACKET_HEADER));

            _logger.Information("ProcessName: {0}, ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                report.ProcessName,
                report.ProcessId,
                report.ThreadId,
                report.DesiredAccess);

            using (var context = new ModelContext())
            {
                /*
                 * This doesn't seem to be the most optimal way to do this, but it works..
                 * Maybe look into it further at somepoint..
                 */
                UserEntity user = new UserEntity(context);

                var newReport = new IllegalHandleOperationEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    IsKernelHandle = report.IsKernelHandle,
                    ProcessId = report.ProcessId,
                    ThreadId = report.ThreadId,
                    DesiredAccess = report.DesiredAccess,
                    ProcessName = report.ProcessName
                };

                newReport.InsertReport();
                context.SaveChanges();
            }
        }
    }
}
