using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using service.Types;
using service.messages;
using System;

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
            MESSAGE_TYPE_REPORT = 1,
            MESSAGE_TYPE_SEND = 2,
            MESSAGE_TYPE_RECEIVE = 3
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
                            case (int)MESSAGE_TYPE.MESSAGE_TYPE_REPORT:
                                Report report = new Report(_pipeServer, _headerSize);
                                break;

                            case (int)MESSAGE_TYPE.MESSAGE_TYPE_RECEIVE:
                                Receive receive = new Receive(_pipeServer, _headerSize);
                                receive.StoreMessage();
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Reading buffer from pipe failed with message: {0}", ex.Message);
                }

                Array.Clear(_header, 0, _headerSize);
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