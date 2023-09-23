using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System;
using System.Reflection.PortableExecutable;
using System.Net.Sockets;
using System.Net;
using System.Net.Http;
using Serilog;

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
#pragma warning disable CS8600
#pragma warning disable CS8603

namespace service
{
    public class Worker : BackgroundService
    {
        private readonly Serilog.ILogger _logger;
        private NamedPipeServerStream _pipeServer;
        private byte[] _buffer;
        private int _bufferSize;
        private static int MAX_BUFFER_SIZE = 8192;

        private static int OK_RESPONSE_SIZE = 4;

        public Worker(Serilog.ILogger logger)
        {
            _logger = logger;

            _pipeServer = new NamedPipeServerStream(
                "DonnaACPipe", 
                PipeDirection.InOut, 
                1, 
                0, 
                PipeOptions.Asynchronous, 
                MAX_BUFFER_SIZE, 
                MAX_BUFFER_SIZE);

            _bufferSize = MAX_BUFFER_SIZE;
            _buffer = new byte[_bufferSize];
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.Information("Windows service starting, waiting for client to connect");

            // to do: verify whos connecting 
            _pipeServer.WaitForConnection();

            _logger.Information("Client connected to the pipe server");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    int numBytesRead = _pipeServer.Read(_buffer, 0, _bufferSize);

                    if (numBytesRead > 0)
                    {
                        _logger.Information("Message received at pipe server with size: {0}", numBytesRead);

                        Client message = new Client(ref _buffer, numBytesRead, _logger);

                        message.SendMessageToServer();

                        ThreadPool.QueueUserWorkItem(state => RelayResponseMessage(ref message));
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error("Reading buffer from pipe failed with message: {0}", ex.Message);
                }

                Array.Clear(_buffer, 0, _bufferSize);
            }
        }

        private void RelayResponseMessage(ref Client message)
        {
            byte[] responseMessage = message.GetResponseFromServer();

            if (responseMessage.Length == OK_RESPONSE_SIZE)
                return;

            _logger.Information("Sending response message to client with size: {0}", responseMessage.Length);

            _pipeServer.Write(responseMessage, 0, responseMessage.Length);
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