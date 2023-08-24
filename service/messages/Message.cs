using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace service.messages
{
    public class Message
    {
        private NamedPipeServerStream _pipeServer;
        private int _packetHeaderSize;
        public Message(NamedPipeServerStream pipeServer, int packetHeaderSize)
        {
            _pipeServer = pipeServer;
            _packetHeaderSize = packetHeaderSize;
        }

        public void ReadPipeBuffer(ref byte[] buffer, int bufferSize )
        {
            _pipeServer.Read(buffer, 0, bufferSize + _packetHeaderSize);
        }
    }
}
