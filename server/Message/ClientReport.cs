using Serilog;
using server.Database.Entity;
using server.Database.Entity.Report;
using server.Database.Entity.Report.Types;
using server.Database.Model;
using server.Types.ClientReport;
using System;
using System.Collections.Generic;
using System.Drawing.Printing;
using System.Linq;
using System.Runtime.InteropServices;
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
            PROCESS_MODULE_VERIFICATION = 10,
            START_ADDRESS_VERIFICATION = 20,
            PAGE_PROTECTION_VERIFICATION = 30,
            PATTERN_SCAN_FAILURE = 40,
            NMI_CALLBACK_FAILURE = 50,
            MODULE_VALIDATION_FAILURE = 60,
            ILLEGAL_HANDLE_OPERATION = 70,
            INVALID_PROCESS_ALLOCATION = 80,
            HIDDEN_SYSTEM_THREAD = 90,
            ILLEGAL_ATTACH_PROCESS = 100
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

            _logger.Information("buffer size: {0}", bufferSize);
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

        private unsafe int GetPacketCount<T>()
        {
            return this._bufferSize / Marshal.SizeOf(typeof(T));
        }

        private unsafe T GetPacketData<T>(int index)
        {
            return Helper.BytesToStructure<T>(this._buffer, index * Marshal.SizeOf(typeof(T)));
        }

        private unsafe int GetPacketCount(int reportCode)
        {
            switch (this._clientReportPacketHeader.reportCode)
            {
                case (int)CLIENT_SEND_REPORT_ID.PROCESS_MODULE_VERIFICATION:
                    //return this._bufferSize / Marshal.SizeOf(typeof(PROCESS_MODULE_VERIFICATION));
                    return 0;
                case (int)CLIENT_SEND_REPORT_ID.START_ADDRESS_VERIFICATION:
                    return this._bufferSize / Marshal.SizeOf(typeof(PROCESS_THREAD_START_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.PAGE_PROTECTION_VERIFICATION:
                    return this._bufferSize / Marshal.SizeOf(typeof(PAGE_PROTECTION_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.PATTERN_SCAN_FAILURE:
                    return this._bufferSize / Marshal.SizeOf(typeof(PATTERN_SCAN_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.NMI_CALLBACK_FAILURE:
                    return this._bufferSize / Marshal.SizeOf(typeof(NMI_CALLBACK_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.MODULE_VALIDATION_FAILURE:
                    return this._bufferSize / Marshal.SizeOf(typeof(MODULE_VALIDATION_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.ILLEGAL_HANDLE_OPERATION:
                    return this._bufferSize / Marshal.SizeOf(typeof(OPEN_HANDLE_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.INVALID_PROCESS_ALLOCATION:
                    return 1;
                case (int)CLIENT_SEND_REPORT_ID.HIDDEN_SYSTEM_THREAD:
                    return this._bufferSize / Marshal.SizeOf(typeof(HIDDEN_SYSTEM_THREAD_FAILURE));
                case (int)CLIENT_SEND_REPORT_ID.ILLEGAL_ATTACH_PROCESS:
                    return this._bufferSize / Marshal.SizeOf(typeof(ATTACH_PROCESS_FAILURE));
                default:
                    return 0;
            }
        }

        public bool HandleMessage()
        {
            if (this._clientReportPacketHeader.reportCode == 0)
            {
                _logger.Error("Failed to get the report packet code");
                return false;
            }

            int reportCount = GetPacketCount(this._clientReportPacketHeader.reportCode);

            _logger.Information("Packet count: {0}", reportCount);

            for (int index = 0 ; index < reportCount; index++)
            {
                switch (this._clientReportPacketHeader.reportCode)
                {
                    case (int)CLIENT_SEND_REPORT_ID.PROCESS_MODULE_VERIFICATION:
                        _logger.Information("REPORT CODE: MODULE_VERIFICATION");
                        break;
                    case (int)CLIENT_SEND_REPORT_ID.START_ADDRESS_VERIFICATION:

                        _logger.Information("REPORT CODE: START_ADDRESS_VERIFICATION");

                        HandleReportStartAddressVerification(
                            index * Marshal.SizeOf(typeof(PROCESS_THREAD_START_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.PAGE_PROTECTION_VERIFICATION:

                        _logger.Information("REPORT CODE: PAGE_PROTECTION_VERIFICATION");

                        HandleReportPageProtection(
                            index * Marshal.SizeOf(typeof(PAGE_PROTECTION_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.PATTERN_SCAN_FAILURE:

                        _logger.Information("REPORT_PATTERN_SCAN_FAILURE");

                        HandleReportPatternScan(
                            index * Marshal.SizeOf(typeof(PATTERN_SCAN_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.NMI_CALLBACK_FAILURE:

                        _logger.Information("REPORT_NMI_CALLBACK_FAILURE");

                        HandleReportNmiCallback(
                            index * Marshal.SizeOf(typeof(NMI_CALLBACK_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.MODULE_VALIDATION_FAILURE:

                        _logger.Information("REPORT_MODULE_VALIDATION_FAILURE");

                        HandleReportSystemModuleValidation(
                            index * Marshal.SizeOf(typeof(MODULE_VALIDATION_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.ILLEGAL_HANDLE_OPERATION:

                        _logger.Information("REPORT_ILLEGAL_HANDLE_OPERATION");

                        HandleReportIllegalHandleOperation(
                            index * Marshal.SizeOf(typeof(OPEN_HANDLE_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.INVALID_PROCESS_ALLOCATION:

                        _logger.Information("REPORT_INVALID_PROCESS_ALLOCATION");

                        HandleInvalidProcessAllocation(
                            index * Marshal.SizeOf(typeof(INVALID_PROCESS_ALLOCATION_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.HIDDEN_SYSTEM_THREAD:

                        _logger.Information("REPORT_HIDDEN_SYSTEM_THREAD");

                        HandleReportHiddenSystemThread(
                            index * Marshal.SizeOf(typeof(HIDDEN_SYSTEM_THREAD_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    case (int)CLIENT_SEND_REPORT_ID.ILLEGAL_ATTACH_PROCESS:

                        _logger.Information("REPORT_ILLEGAL_ATTACH_PROCESS");

                        HandleReportAttachProcess(
                            index * Marshal.SizeOf(typeof(ATTACH_PROCESS_FAILURE)) + 
                            index * Marshal.SizeOf(typeof(PACKET_HEADER)));
                        break;

                    default:
                        _logger.Information("Report code not handled yet");
                        break;
                }
            }

            SetResponsePacketData(1);
            return true;
        }

        unsafe public void HandleReportIllegalHandleOperation(int offset)
        {
            OPEN_HANDLE_FAILURE report = 
                Helper.BytesToStructure<OPEN_HANDLE_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            if (report.DesiredAccess == 0 &&
                report.ProcessId == 0 &&
                report.IsKernelHandle == 0 &&
                report.ProcessId == 0)
            {
                return;
            }

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

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.ILLEGAL_HANDLE_OPERATION
                };

                newReport.InsertReport();

                var reportTypeIllegalHandleOperation = new ReportTypeIllegalHandleOperationEntity(context)
                {
                    Report = newReport,
                    IsKernelHandle = report.IsKernelHandle,
                    ProcessId = report.ProcessId,
                    ThreadId = report.ThreadId,
                    DesiredAccess = report.DesiredAccess,
                    ProcessName = report.ProcessName
                };

                reportTypeIllegalHandleOperation.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportStartAddressVerification(int offset)
        {
            PROCESS_THREAD_START_FAILURE report = 
                Helper.BytesToStructure<PROCESS_THREAD_START_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("ThreadId: {0}, ThreadStartAddress: {1:x}",
                report.ThreadId,
                report.StartAddress);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.START_ADDRESS_VERIFICATION
                };

                newReport.InsertReport();

                var reportTypeStartAddress = new StartAddressEntity(context)
                {
                    Report = newReport,
                    ThreadId = report.ThreadId,
                    ThreadStartAddress = report.StartAddress
                };

                reportTypeStartAddress.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportPageProtection(int offset)
        {
            PAGE_PROTECTION_FAILURE report =
                Helper.BytesToStructure<PAGE_PROTECTION_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("Page base address: {0:x}, allocation protection: {1:x}, allocation state: {2:x}, allocationtype: {3:x}",
                report.PageBaseAddress,
                report.AllocationProtection,
                report.AllocationState,
                report.AllocationType);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.PAGE_PROTECTION_VERIFICATION
                };

                newReport.InsertReport();

                var reportTypePageProtection = new PageProtectionEntity(context)
                {
                    Report = newReport,
                    PageBaseAddress = report.PageBaseAddress,
                    AllocationProtection = report.AllocationProtection,
                    AllocationState = report.AllocationState,
                    AllocationType = report.AllocationType
                };

                reportTypePageProtection.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportPatternScan(int offset)
        {
            PATTERN_SCAN_FAILURE report =
                Helper.BytesToStructure<PATTERN_SCAN_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("signature id: {0}, address: {1:x}",
                report.SignatureId,
                report.Address);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.PATTERN_SCAN_FAILURE
                };

                newReport.InsertReport();

                var reportTypePatternScan = new PatternScanEntity(context)
                {
                    Report = newReport,
                    SignatureId = report.SignatureId,
                    Address = report.Address
                };

                reportTypePatternScan.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportNmiCallback(int offset)
        {
            NMI_CALLBACK_FAILURE report =
                Helper.BytesToStructure<NMI_CALLBACK_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("were nmis disabled: {0}, kthread: {1:x}, invalid rip: {2:x}",
                report.WereNmisDisabled,
                report.KThreadAddress,
                report.InvalidRip);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.NMI_CALLBACK_FAILURE
                };

                newReport.InsertReport();

                var reportTypeNmiCallback = new NmiCallbackEntity(context)
                {
                    Report = newReport,
                    WereNmisDisabled = report.WereNmisDisabled,
                    KThreadAddress = report.KThreadAddress,
                    InvalidRip = report.InvalidRip
                };

                reportTypeNmiCallback.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportSystemModuleValidation(int offset)
        {
            MODULE_VALIDATION_FAILURE report =
                Helper.BytesToStructure<MODULE_VALIDATION_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("report type: {0}, driver base: {1:x}, size: {2}, module name: {3}",
                report.ReportType,
                report.DriverBaseAddress,
                report.DriverSize,
                report.ModuleName);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.MODULE_VALIDATION_FAILURE
                };

                newReport.InsertReport();

                var reportTypeSystemModuleValidation = new SystemModuleValidationEntity(context)
                {
                    Report = newReport,
                    ReportType = report.ReportType,
                    DriverBaseAddress = report.DriverBaseAddress,
                    DriverSize = report.DriverSize,
                    ModuleName = report.ModuleName
                };

                reportTypeSystemModuleValidation.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportHiddenSystemThread(int offset)
        {
            HIDDEN_SYSTEM_THREAD_FAILURE report =
                Helper.BytesToStructure<HIDDEN_SYSTEM_THREAD_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("found in kthread list: {0}, found in pspcidtable: {1}, thread address: {2:x}, thread id: {3:x}",
                report.FoundInKThreadList,
                report.FoundInPspCidTable,
                report.ThreadAddress,
                report.ThreadId);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.HIDDEN_SYSTEM_THREAD
                };

                newReport.InsertReport();

                var reportTypeHiddenSystemThread = new HiddenSystemThreadEntity(context)
                {
                    Report = newReport,
                    FoundInKThreadList = report.FoundInKThreadList,
                    FoundInPspCidTable = report.FoundInPspCidTable,
                    ThreadAddress = report.ThreadAddress,
                    ThreadId = report.ThreadId
                };

                reportTypeHiddenSystemThread.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleReportAttachProcess(int offset)
        {
            ATTACH_PROCESS_FAILURE report =
                Helper.BytesToStructure<ATTACH_PROCESS_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);

            _logger.Information("thread id: {0:x}, thread address: {1:x}",
                report.ThreadId,
                report.ThreadAddress);

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.ILLEGAL_ATTACH_PROCESS
                };

                newReport.InsertReport();

                var reportTypeAttachProcess = new AttachProcessEntity(context)
                {
                    Report = newReport,
                    ThreadId = report.ThreadId,
                    ThreadAddress = report.ThreadAddress,
                };

                reportTypeAttachProcess.InsertReport();

                context.SaveChanges();
            }
        }

        unsafe public void HandleInvalidProcessAllocation(int offset)
        {
/*            INVALID_PROCESS_ALLOCATION_FAILURE report =
                Helper.BytesToStructure<INVALID_PROCESS_ALLOCATION_FAILURE>(_buffer, sizeof(PACKET_HEADER) + offset);*/

            byte[] processStructure = new byte[4096];

            Helper.CopyMemory(ref _buffer, ref processStructure, 4096, sizeof(PACKET_HEADER) + offset);

            _logger.Information("received invalid process allocation structure");

            using (var context = new ModelContext())
            {
                UserEntity user = new UserEntity(context);

                var newReport = new ReportEntity(context)
                {
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id),
                    ReportCode = (int)CLIENT_SEND_REPORT_ID.INVALID_PROCESS_ALLOCATION
                };

                newReport.InsertReport();

                var reportTypeInvalidProcessAllocation = new InvalidProcessAllocationEntity(context)
                {
                    Report = newReport,
                    ProcessStructure = processStructure
                };

                reportTypeInvalidProcessAllocation.InsertReport();

                context.SaveChanges();
            }
        }
    }
}
