using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace service.messages
{
    public class Send : Message
    {
        private byte[] _buffer;
        private static int SEND_BUFFER_SIZE = 8192;

        private enum SEND_TYPE
        {
            SEND_SIGNATURES_TO_SCAN = 10
        }

        public Send(NamedPipeServerStream pipeServer, int pipePacketHeaderSize)
            : base(pipeServer, pipePacketHeaderSize)
        {
            _buffer = new byte[SEND_BUFFER_SIZE];
        }

    }
}
