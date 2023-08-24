using Serilog;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace service.messages
{
    public class Receive : Message
    {
        private byte[] _buffer;
        private static int RECEIVE_BUFFER_SIZE = 8192;

        private enum RECEIVE_TYPE
        {
            SERVER_SEND_MODULE_INTEGRITY_CHECK = 10
        }

        public Receive(NamedPipeServerStream pipeServer, int pipePacketHeaderSize)
            : base(pipeServer, pipePacketHeaderSize)
        {
            _buffer = new byte[RECEIVE_BUFFER_SIZE];

            StoreMessage();
        }

        public void StoreMessage()
        {
            ReadPipeBuffer(ref _buffer, RECEIVE_BUFFER_SIZE);

            Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER header =
                GetPacketHeader<Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER>(ref _buffer);

            PrintPacketInformation(header);
        }

        private void PrintPacketInformation(Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER header)
        {
            Log.Information("Incoming packet count: {0:x}, current packet num: {1:x}, current packet size: {2:x}, total packet size: {3:x}",
                header.total_incoming_packet_count,
                header.current_packet_number,
                header.packet_size,
                header.total_incoming_packet_size);
        }
    }
}
