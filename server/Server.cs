using System.IO;
using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using Serilog;
using server.Message;

namespace server
{
    public class Server
    {
        private IPEndPoint _ipEndPoint;
        private TcpListener _tcpListener;
        private ILogger _logger;

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
                TcpClient client = await _tcpListener.AcceptTcpClientAsync();

                NetworkStream _stream = client.GetStream();
                TcpClient clientReference = client;

                byte[] buffer = new byte[2048];
                int bytesRead = 0;

                using (MemoryStream stream = new MemoryStream())
                {
                    while (_stream.DataAvailable)
                    {
                        bytesRead = _stream.Read(buffer, 0, buffer.Length);
                        stream.Write(buffer, 0, bytesRead);
                    }

                    byte[] message = stream.ToArray();

                    ThreadPool.QueueUserWorkItem(state => DispatchMessage(state, clientReference, message, message.Length));
                }
            }
        }

        private void DispatchMessage(Object? stateInfo, TcpClient client, byte[] buffer, int bufferSize)
        {
            MessageHandler message = new MessageHandler(client, buffer, bufferSize, _logger);
        }
    }
}