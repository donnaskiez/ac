using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using System.Runtime.CompilerServices;

namespace service
{
    public struct TestReport
    {
        public UInt64 Num1;
        public UInt64 Num2;
    }
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private NamedPipeServerStream _pipeServer;
        private int _threadId;
        private byte[] _buffer;
        private Mutex _mutex;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            _buffer = new byte[1024];
            _pipeServer = new NamedPipeServerStream("DonnaACPipe", PipeDirection.InOut, 1);
            _threadId = Thread.CurrentThread.ManagedThreadId;
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Windows service starting, waiting for client to connect");

            _pipeServer.WaitForConnection();

            _logger.LogInformation("Client connected to the pipe server");

            while (!stoppingToken.IsCancellationRequested)
            { 
                try
                {
                    if (_pipeServer.Read(_buffer, 0, 1024) > 0)
                    {
                        _logger.LogInformation("Report received, decoding buffer");
                        await TranslatePipeBuffer();
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
            var packet = BytesToStructure<TestReport>();
            Array.Clear(_buffer, 0, _buffer.Length);
            _logger.LogInformation("Num1: {0}, Num2: {1}", packet.Num1, packet.Num2);
        }

        private T BytesToStructure<T>()
        {
            int size = Marshal.SizeOf(typeof(T));

            IntPtr ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.Copy(_buffer, 0, ptr, size);
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