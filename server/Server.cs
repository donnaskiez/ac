using System.IO;
using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using server;
using Serilog;

namespace server
{
    public class Server
    {
        private IPEndPoint _ipEndPoint;
        private TcpListener _tcpListener;
        private ILogger _logger;

        private const int MAX_BUFFER_SIZE = 8192;

        public Server(ILogger logger)
        {
            _ipEndPoint = new IPEndPoint(IPAddress.Any, 8888);
            _tcpListener = new TcpListener(_ipEndPoint);
            _logger = logger;
        }

        public async Task Listen()
        {
            _tcpListener.Start();

            _logger.Information("Listening for incoming connections...");

            while (true)
            {
                using TcpClient _client = await _tcpListener.AcceptTcpClientAsync();
                NetworkStream _stream = _client.GetStream();

                byte[] buffer = new byte[MAX_BUFFER_SIZE];
                int bufferSize = 0;
                NetworkStream clientStreamReference = _stream;

                bufferSize = _stream.Read(buffer, 0, MAX_BUFFER_SIZE);

                ThreadPool.QueueUserWorkItem(state => DispatchMessage(state, clientStreamReference, buffer, bufferSize) );
            }
        }

        private void DispatchMessage(Object? stateInfo, NetworkStream clientStreamReference, byte[] buffer, int bufferSize)
        {
            Message message = new Message(clientStreamReference, buffer, bufferSize, _logger);
        }
    }
}