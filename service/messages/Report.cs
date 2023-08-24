using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using service;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using service.Types.Reports;
using Serilog;

namespace service.messages
{
    public class Report : Message
    {
        private byte[] _buffer;
        private static int REPORT_BUFFER_SIZE = 1024;

        private enum REPORT_TYPE
        {
            REPORT_PROCESS_MODULE_FAILURE = 10,
            REPORT_PROCESS_THREAD_START_ADDRESS_FAILURE = 20,
            REPORT_PAGE_PROTECTION_VERIFICATION = 30,
            REPORT_PATTERN_SCAN_FAILURE = 40,
            REPORT_NMI_CALLBACK_FAILURE = 50,
            REPORT_KERNEL_MODULE_FAILURE = 60,
            REPORT_OPEN_HANDLE_FAILURE_REPORT = 70
        }

        public Report(NamedPipeServerStream pipeServer, int pipePacketHeaderSize)
            : base(pipeServer, pipePacketHeaderSize)
        {
            _buffer = new byte[REPORT_BUFFER_SIZE];

            ReadPipeBuffer(ref _buffer, REPORT_BUFFER_SIZE);

            ConvertByteReportIntoStructure();
        }

        // This is fine for now as the report header is only an int
        private int GetReportType()
        {
            return BitConverter.ToInt32( _buffer, 0 );
        }
        private Task ConvertByteReportIntoStructure()
        {
            int reportType = GetReportType();

            Log.Information("REport type: {0}", reportType);

            if (!Enum.IsDefined(typeof(REPORT_TYPE), reportType))
            {
                Log.Error("Enum value of {0} is invalid.", reportType);

                return Task.CompletedTask;
            }

            switch(reportType)
            {
                case (int)REPORT_TYPE.REPORT_PROCESS_MODULE_FAILURE:
                    PrintProcessModuleFailureReport();
                    break;
                case (int)REPORT_TYPE.REPORT_PROCESS_THREAD_START_ADDRESS_FAILURE:
                    PrintStartAddressFailure();
                    break;
                case (int)REPORT_TYPE.REPORT_PAGE_PROTECTION_VERIFICATION:
                    PrintPageProtectionFailure();
                    break;
                case (int)REPORT_TYPE.REPORT_PATTERN_SCAN_FAILURE:
                    PrintPatternScanFailure();
                    break;
                case (int)REPORT_TYPE.REPORT_NMI_CALLBACK_FAILURE:
                    PrintNmiCallbackFailure();
                    break;
                case (int)REPORT_TYPE.REPORT_KERNEL_MODULE_FAILURE:
                    PrintKernelModuleFailure();
                    break;
                case (int)REPORT_TYPE.REPORT_OPEN_HANDLE_FAILURE_REPORT:
                    PrintOpenHandleFailure();
                    break;
                default:
                    break;
            }

            return Task.CompletedTask;
        }

        private void PrintProcessModuleFailureReport()
        {
            MODULE_VERIFICATION_CHECKSUM_FAILURE report = Helper.BytesToStructure<MODULE_VERIFICATION_CHECKSUM_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, Base address: {1:x}, Size: {2:x}, Name: ",
                report.ReportCode,
                report.ModuleBaseAddress,
                report.ModuleSize);
        }

        private void PrintStartAddressFailure()
        {
            PROCESS_THREAD_START_FAILURE report = Helper.BytesToStructure<PROCESS_THREAD_START_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, Thread Id: {1:x}, Start Address: {2:x}",
                report.ReportCode,
                report.ThreadId,
                report.StartAddress);
        }

        private void PrintPageProtectionFailure()
        {
            PAGE_PROTECTION_FAILURE report = Helper.BytesToStructure<PAGE_PROTECTION_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, page base address: {1:x}, allocation protection {2:x}, allocation state: {3:x}, allocation type: {4:x}",
                report.ReportCode,
                report.PageBaseAddress,
                report.AllocationProtection,
                report.AllocationState,
                report.AllocationType);
        }

        private void PrintPatternScanFailure()
        {
            PATTERN_SCAN_FAILURE report = Helper.BytesToStructure<PATTERN_SCAN_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, signature id: {1:x}, Address: {2:x}",
                report.ReportCode,
                report.SignatureId,
                report.Address);
        }

        private void PrintNmiCallbackFailure()
        {
            NMI_CALLBACK_FAILURE report = Helper.BytesToStructure<NMI_CALLBACK_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, WereNmisDisabled: {1:x}, KThreadAddress: {2:x}, InvalidRip: {3:x}",
                report.ReportCode,
                report.WereNmisDisabled,
                report.KThreadAddress,
                report.InvalidRip);
        }
        
        private void PrintKernelModuleFailure()
        {
            MODULE_VALIDATION_FAILURE report = Helper.BytesToStructure<MODULE_VALIDATION_FAILURE>(ref _buffer);

            Log.Information("Report code: {0}, REportType: {1:x}, DriverBaseAddress: {2:x}, DriverSize: {3:x}",
                report.ReportCode,
                report.ReportType,
                report.DriverBaseAddress,
                report.DriverSize);
        }

        private void PrintOpenHandleFailure()
        {
            OPEN_HANDLE_FAILURE_REPORT report = Helper.BytesToStructure<OPEN_HANDLE_FAILURE_REPORT>(ref _buffer);

            Log.Information("Report code: {0}, ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                report.ReportCode,
                report.ProcessId,
                report.ThreadId,
                report.DesiredAccess);
        }

    }
}
