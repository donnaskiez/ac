using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using server;

namespace server
{
    public class Server
    {
        private IPEndPoint _ipEndPoint;
        private TcpListener _tcpListener;

        public Server()
        {
            _ipEndPoint = new IPEndPoint(IPAddress.Any, 8888);
            _tcpListener = new TcpListener(_ipEndPoint);
        }

        public async Task Listen()
        {
            _tcpListener.Start();

            using TcpClient _client = await _tcpListener.AcceptTcpClientAsync();

            Thread dispatchThread = new Thread(() => new Dispatch(_client, _client.GetStream()));
            dispatchThread.Start();
        }
    }
}