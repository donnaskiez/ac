using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Message
{
    public interface IClientMessage
    {
        /// <summary>
        /// Implements a function that returns the packet header for the type of client 
        /// message it is handling. Is an unsafe function because we are taking the
        /// size of struct which makes c# unhappy.
        /// </summary>
        unsafe void GetPacketHeader();
        /// <summary>
        /// Function which implements the core logic to handle a message received from 
        /// the client. Should take care of all major actions when handling the message.
        /// </summary>
        bool HandleMessage();
        /// <summary>
        /// Function that returns the response packet in the form of a byte array.
        /// </summary>
        byte[] GetResponsePacket();
        
    }
}
