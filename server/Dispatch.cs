using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace server
{
    public class Dispatch
    {
        private TcpClient _client;
        private NetworkStream _stream;
        private byte[] _buffer;

        public Dispatch(TcpClient client, NetworkStream stream)
        {
            _client = client;
            _stream = stream;
            _buffer = new byte[1024];

            this.AcceptMessage();
        }

        private void AcceptMessage()
        {
            _stream.BeginRead(_buffer, 0, 1024, null, null);
        }
    }
}
