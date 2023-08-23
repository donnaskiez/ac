using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using service;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;

namespace service.messages
{
    public class Report
    {
        private NamedPipeServerStream _pipeServer;
        private readonly ILogger<Report> _logger;

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

        public Report(
            ILogger<Report> logger, 
            NamedPipeServerStream pipeServer,
            int pipePacketHeaderSize
            )
        {
            _logger = logger;
            _pipeServer = pipeServer;
            _buffer = new byte[REPORT_BUFFER_SIZE];

            ReadReportIntoBuffer(pipePacketHeaderSize);
        }

        private void ReadReportIntoBuffer(int pipePacketHeaderSize)
        {
            _pipeServer.Read(_buffer, 0, REPORT_BUFFER_SIZE + pipePacketHeaderSize);
        }

        // This is fine for now as the report header is only an int
        private int GetReportType()
        {
            return BitConverter.ToInt32( _buffer, 0 );
        }
        private Task ConvertByteReportIntoStructure()
        {
            int reportType = GetReportType();

            if (!Enum.IsDefined(typeof(REPORT_TYPE), reportType))
            {
                _logger.LogError("Enum value of {0} is invalid.", reportType);

                return Task.CompletedTask;
            }

            switch(reportType)
            {
                case (int)REPORT_TYPE.REPORT_PROCESS_MODULE_FAILURE:
                    break;
                case (int)REPORT_TYPE.REPORT_PROCESS_THREAD_START_ADDRESS_FAILURE:
                    break;
                case (int)REPORT_TYPE.REPORT_PAGE_PROTECTION_VERIFICATION:
                    break;
                case (int)REPORT_TYPE.REPORT_PATTERN_SCAN_FAILURE:
                    break;
                case (int)REPORT_TYPE.REPORT_NMI_CALLBACK_FAILURE:
                    break;
                case (int)REPORT_TYPE.REPORT_KERNEL_MODULE_FAILURE:
                    break;
                case (int)REPORT_TYPE.REPORT_OPEN_HANDLE_FAILURE_REPORT:
                    break;
                default:
                    break;
            }

            return Task.CompletedTask;
        }
    }
}
