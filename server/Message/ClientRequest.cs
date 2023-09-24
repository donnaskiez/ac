using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static server.Message.MessageHandler;

namespace server.Message
{
    public class ClientRequest : IClientMessage
    {
        private readonly ILogger _logger;
        private byte[] _buffer;
        private int _bufferSize;
        private CLIENT_REQUEST_HEADER _header;

        private enum CLIENT_REQUEST_ID
        {
            BLACKLISTED_SIGNATURES = 10,
            WINDOWS_VERSION_STRUCTURE_OFFSETS = 20
        }

        private struct CLIENT_REQUEST_HEADER
        {
            public int RequestId;
        }

        public ClientRequest(ILogger logger, ref byte[] buffer, int bufferSize)
        {
            this._logger = logger;
            this._buffer = buffer;
            this._bufferSize = bufferSize;
        }

        public bool HandleMessage()
        {
            throw new NotImplementedException();
        }

        public unsafe void GetPacketHeader()
        {
            this._header =
                Helper.BytesToStructure<CLIENT_REQUEST_HEADER>(this._buffer, Marshal.SizeOf(typeof(PACKET_HEADER)));
        }

        public byte[] GetResponsePacket()
        {
            throw new NotImplementedException();
        }
    }
}
