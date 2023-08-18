using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace service
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private NamedPipeServerStream _pipeServer;
        private int _threadId;
        private byte[] _buffer;

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
            int bytesRead = 0;
            int offset = 0;

            _logger.LogInformation("Windows service starting, waiting for client to connect");

            while (!stoppingToken.IsCancellationRequested)
            {
                _pipeServer.WaitForConnection();

                _logger.LogInformation("Client connected to the pipe server");

                try
                {
                    while ((bytesRead = _pipeServer.Read(_buffer, offset, unchecked((int)_pipeServer.Length))) > 0)
                    {
                        offset += bytesRead;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError("Reading buffer from pipe failed with status: {1}", ex.Message);
                }
            }
        }
    }
}
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously