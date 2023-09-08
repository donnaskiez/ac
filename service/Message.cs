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
        private byte[] _buffer;
        private int _bufferSize;
        public Message(byte[] buffer, int bufferSize)
        {
            _bufferSize = bufferSize;
            _buffer = buffer;
        }

        public void DispatchMessage()
        {
            Client client = new Client(_buffer, _bufferSize);
            client.SendMessageToServer();
        }

        public T GetPacketHeader<T>(ref byte[] buffer)
        {
            return Helper.BytesToStructure<T>(ref buffer, 0);
        }
    }
}
