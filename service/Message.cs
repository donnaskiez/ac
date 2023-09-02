using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using service;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace service
{
    public class Message
    {
        private NamedPipeServerStream _pipeServer;
        private byte[] _buffer;
        private int _bufferSize;
        public Message(NamedPipeServerStream pipeServer)
        {
            _pipeServer = pipeServer;
            _bufferSize = _pipeServer.InBufferSize;
            _buffer = new byte[_bufferSize];
        }

        public async Task ReadPipeBuffer()
        {
            await _pipeServer.ReadAsync(_buffer, 0, _bufferSize);
        }

        public void SendMessageToServer()
        {
            Client client = new Client(_buffer, _bufferSize);
            client.SendMessageToServer();
        }

        public T GetPacketHeader<T>(ref byte[] buffer)
        {
            return Helper.BytesToStructure<T>(ref buffer);
        }
    }
}
