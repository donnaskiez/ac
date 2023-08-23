using System.IO.Pipes;
using System.Runtime.CompilerServices;
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

        private byte[] _header;
        private int _headerSize;

        private enum MESSAGE_TYPE
        {
            MESSAGE_TYPE_REPORT,
            MESSAGE_TYPE_RECEIVE,
            MESSAGE_TYPE_SEND,
        }

        struct PIPE_PACKET_HEADER
        {
            int message_type;
        };

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            _pipeServer = new NamedPipeServerStream("DonnaACPipe", PipeDirection.InOut, 1);

            unsafe 
            {
                _headerSize = sizeof(PIPE_PACKET_HEADER); 
            }

            _header = new byte[_headerSize];
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Windows service starting, waiting for client to connect");

            // to do: verify whos connecting 
            _pipeServer.WaitForConnection();

            _logger.LogInformation("Client connected to the pipe server");

            while (!stoppingToken.IsCancellationRequested)
            { 
                try
                {
                    if (_pipeServer.Read(_header, 0, _headerSize) > 0)
                    {
                        // for now the header is only an int... LOL
                        int header = BitConverter.ToInt32(_header, 0);

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
                case REPORT_PROCESS_MODULE_FAILURE:

                    var checksumFailurePacket = BytesToStructure<MODULE_VERIFICATION_CHECKSUM_FAILURE>();

                    unsafe
                    {
                        _logger.LogInformation("Report code: {0}, Base address: {1:x}, Size: {2:x}, Name: ",
                            checksumFailurePacket.ReportCode,
                            checksumFailurePacket.ModuleBaseAddress,
                            checksumFailurePacket.ModuleSize);
                    }

                    goto end;

                case REPORT_PROCESS_THREAD_START_ADDRESS_FAILURE:

                    var startAddressFailurePacket = BytesToStructure<PROCESS_THREAD_START_FAILURE>();

                    _logger.LogInformation("Report code: {0}, Thread Id: {1:x}, Start Address: {2:x}",
                        startAddressFailurePacket.ReportCode,
                        startAddressFailurePacket.ThreadId,
                        startAddressFailurePacket.StartAddress);

                    goto end;

                case REPORT_PAGE_PROTECTION_VERIFICATION:

                    var pageProtectionFailure = BytesToStructure<PAGE_PROTECTION_FAILURE>();

                    _logger.LogInformation("Report code: {0}, page base address: {1:x}, allocation protection {2:x}, allocation state: {3:x}, allocation type: {4:x}",
                        pageProtectionFailure.ReportCode,
                        pageProtectionFailure.PageBaseAddress,
                        pageProtectionFailure.AllocationProtection,
                        pageProtectionFailure.AllocationState,
                        pageProtectionFailure.AllocationType);

                    goto end;

                case REPORT_PATTERN_SCAN_FAILURE:

                    var patternScanFailure = BytesToStructure<PATTERN_SCAN_FAILURE>();

                    _logger.LogInformation("Report code: {0}, signature id: {1:x}, Address: {2:x}",
                        patternScanFailure.ReportCode,
                        patternScanFailure.SignatureId,
                        patternScanFailure.Address);

                    goto end;

                case REPORT_NMI_CALLBACK_FAILURE:

                    var nmiCallbackFailure = BytesToStructure<NMI_CALLBACK_FAILURE>();

                    _logger.LogInformation("Report code: {0}, WereNmisDisabled: {1:x}, KThreadAddress: {2:x}, InvalidRip: {3:x}",
                        nmiCallbackFailure.ReportCode,
                        nmiCallbackFailure.WereNmisDisabled,
                        nmiCallbackFailure.KThreadAddress,
                        nmiCallbackFailure.InvalidRip);

                    goto end;

                case REPORT_KERNEL_MODULE_FAILURE:

                    var kernelModuleFailure = BytesToStructure<MODULE_VALIDATION_FAILURE>();

                    _logger.LogInformation("Report code: {0}, REportType: {1:x}, DriverBaseAddress: {2:x}, DriverSize: {3:x}",
                        kernelModuleFailure.ReportCode,
                        kernelModuleFailure.ReportType,
                        kernelModuleFailure.DriverBaseAddress,
                        kernelModuleFailure.DriverSize);

                    goto end;

                case REPORT_OPEN_HANDLE_FAILURE_REPORT:

                    var openHandleFailure = BytesToStructure<OPEN_HANDLE_FAILURE_REPORT>();

                    _logger.LogInformation("Report code: {0}, ProcessID: {1:x}, ThreadId: {2:x}, DesiredAccess{3:x}",
                        openHandleFailure.ReportCode,
                        openHandleFailure.ProcessId,
                        openHandleFailure.ThreadId,
                        openHandleFailure.DesiredAccess);

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

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);
        public static uint GetNamedPipeClientProcId(NamedPipeServerStream PipeServer)
        {
            UInt32 procId;
            IntPtr pipeHandle = PipeServer.SafePipeHandle.DangerousGetHandle();

            if (GetNamedPipeClientProcessId(pipeHandle, out procId))
                return procId;

            return 0;
        }
    }
}
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
#pragma warning restore CS8600
#pragma warning restore CS8603