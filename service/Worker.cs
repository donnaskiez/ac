using System.IO.Pipes;
using System.Runtime.InteropServices;
using service.Types;

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
#pragma warning disable CS8600
#pragma warning disable CS8603

namespace service
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private NamedPipeServerStream _pipeServer;
        private byte[] _buffer;
        private byte[] _headerBuf;
        private int _headerBufSize;

        private const int REPORT_CODE_MODULE_VERIFICATION = 10;
        private const int REPORT_CODE_START_ADDRESS_VERIFICATION = 20;
        private const int REPORT_PAGE_PROTECTION_VERIFICATION = 30;
        private const int REPORT_PATTERN_SCAN_FAILURE = 40;

        private const int MESSAGE_TYPE_REPORT = 1;
        private const int MESSAGE_TYPE_REQUEST = 2;

        private int PIPE_BUFFER_READ_SIZE;

        struct PIPE_PACKET_HEADER
        {
            int message_type;
        };

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            _buffer = new byte[1024];
            unsafe { _headerBufSize = sizeof(PIPE_PACKET_HEADER); }
            _headerBuf = new byte[_headerBufSize]; 
            _pipeServer = new NamedPipeServerStream("DonnaACPipe", PipeDirection.InOut, 1);
            PIPE_BUFFER_READ_SIZE = 1024 - _headerBufSize;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Windows service starting, waiting for client to connect");

            // to do: verify whos connecting 
            _pipeServer.WaitForConnection();

            _logger.LogInformation("Client connected to the pipe server");

            int header = 0;

            while (!stoppingToken.IsCancellationRequested)
            { 
                try
                {
                    if (_pipeServer.Read(_headerBuf, 0, _headerBufSize) > 0)
                    {
                        // for now the header is only an int... LOL
                        header = BitConverter.ToInt32(_headerBuf, 0);

                        _logger.LogInformation("Message received with id: {0}", header);

                        switch (header)
                        {
                            case MESSAGE_TYPE_REPORT:

                                _pipeServer.Read(_buffer, 0, PIPE_BUFFER_READ_SIZE + _headerBufSize);
                                await TranslatePipeBuffer();
                                break;

                            case MESSAGE_TYPE_REQUEST:

                                _logger.LogInformation("Request received lLOL");
                                Array.Clear(_buffer, 0, _buffer.Length);
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Reading buffer from pipe failed with message: {0}", ex.Message);
                }
            }
        }

        private async Task TranslatePipeBuffer()
        {
            int reportCode = BitConverter.ToInt32(_buffer, 0);

            _logger.LogInformation("Report received with code: {0}", reportCode);

            switch (reportCode)
            {
                case REPORT_CODE_MODULE_VERIFICATION:

                    var checksumFailurePacket = BytesToStructure<MODULE_VERIFICATION_CHECKSUM_FAILURE>();

                    unsafe
                    {
                        _logger.LogInformation("Report code: {0}, Base address: {1}, Size: {2}, Name: ",
                            checksumFailurePacket.ReportCode,
                            checksumFailurePacket.ModuleBaseAddress,
                            checksumFailurePacket.ModuleSize);
                    }

                    goto end;

                case REPORT_CODE_START_ADDRESS_VERIFICATION:

                    var startAddressFailurePacket = BytesToStructure<PROCESS_THREAD_START_FAILURE>();

                    _logger.LogInformation("Report code: {0}, Thread Id: {1}, Start Address: {2}",
                        startAddressFailurePacket.ReportCode,
                        startAddressFailurePacket.ThreadId,
                        startAddressFailurePacket.StartAddress);

                    goto end;

                case REPORT_PAGE_PROTECTION_VERIFICATION:

                    var pageProtectionFailure = BytesToStructure<PAGE_PROTECTION_FAILURE>();

                    _logger.LogInformation("Report code: {0}, page base address: {1}, allocation protection {2}, allocation state: {3}, allocation type: {4}",
                        pageProtectionFailure.ReportCode,
                        pageProtectionFailure.PageBaseAddress,
                        pageProtectionFailure.AllocationProtection,
                        pageProtectionFailure.AllocationState,
                        pageProtectionFailure.AllocationType);

                    goto end;

                case REPORT_PATTERN_SCAN_FAILURE:

                    var patternScanFailure = BytesToStructure<PATTERN_SCAN_FAILURE>();

                    _logger.LogInformation("Report code: {0}, signature id: {1}, Address: {2}",
                        patternScanFailure.ReportCode,
                        patternScanFailure.SignatureId,
                        patternScanFailure.Address);

                    goto end;

                default:
                    _logger.LogError("Invalid report code received");
                    goto end;

            }
        end:
            Array.Clear(_buffer, 0, _buffer.Length);
        }

        private T BytesToStructure<T>()
        {
            int size = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(size);

            try
            {
                unsafe { Marshal.Copy(_buffer, 0, ptr, size); }
                return (T)Marshal.PtrToStructure(ptr, typeof(T));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
#pragma warning restore CS8600
#pragma warning restore CS8603