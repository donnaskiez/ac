using Serilog;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace service.messages
{
    public class Receive : Message
    {
        private byte[] _buffer;
        private static int RECEIVE_BUFFER_SIZE = 8192;
        private IntPtr _receiveMessageAllocation;

        private enum RECEIVE_TYPE
        {
            SERVER_SEND_MODULE_INTEGRITY_CHECK = 10
        }

        public Receive(NamedPipeServerStream pipeServer, int pipePacketHeaderSize)
            : base(pipeServer, pipePacketHeaderSize)
        {
            _buffer = new byte[RECEIVE_BUFFER_SIZE];
        }

        public void StoreMessage()
        {
            ReadPipeBuffer(ref _buffer, RECEIVE_BUFFER_SIZE);

            Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER header = GetPacketHeader();

            _receiveMessageAllocation = Marshal.AllocHGlobal((int)header.total_incoming_packet_size);

            int incoming_packets_count = header.total_incoming_packet_count;

            Log.Information("Incoming packet count: {0}", incoming_packets_count);

            if (incoming_packets_count > 1)
            {
                for (int i=0; i < incoming_packets_count; i++)
                {
                    Marshal.Copy(_buffer, 0, _receiveMessageAllocation + i * RECEIVE_BUFFER_SIZE, (int)header.packet_size);

                    Array.Clear(_buffer);

                    ReadPipeBuffer(ref _buffer, RECEIVE_BUFFER_SIZE);

                    Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER test = GetPacketHeader();

                    Log.Information("Packet number: {0}, packet size: {1}", test.current_packet_number, test.packet_size);
                }
            }
            else
            {
                Marshal.Copy(_buffer, 0, _receiveMessageAllocation, (int)header.total_incoming_packet_size);
            }
        }

        private Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER GetPacketHeader()
        {
            return Helper.BytesToStructure<Types.Receive.PIPE_PACKET_SEND_EXTENSION_HEADER>(ref _buffer);
        }
    }
}
