using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using Serilog;
using server.Database.Entity;
using server.Database.Model;
using server.Types.ClientSend;
using static server.Message.MessageHandler;

namespace server.Message
{
    public class ClientSend : IClientMessage
    {
        private readonly ILogger _logger;
        private byte[] _buffer;
        private int _bufferSize;
        private int _sendId;
        private PACKET_HEADER _packetHeader;
        private CLIENT_SEND_PACKET_HEADER _clientSendPacketHeader;
        private CLIENT_SEND_PACKET_RESPONSE _responsePacket;

        private enum CLIENT_SEND_REQUEST_ID
        {
            SYSTEM_INFORMATION = 10
        }

        private struct CLIENT_SEND_PACKET_HEADER
        {
            public int RequestId;
            public int PacketSize;
        };

        private struct CLIENT_SEND_PACKET_RESPONSE
        {
            public int RequestId;
            public int CanUserProceed;
            public int reason;
        }

        public ClientSend(ILogger logger, ref byte[] buffer, int bufferSize, PACKET_HEADER packetHeader)
        {
            this._logger = logger;
            this._buffer = buffer;
            this._bufferSize = bufferSize;
            this._packetHeader = packetHeader;
            this._responsePacket = new CLIENT_SEND_PACKET_RESPONSE();
            this.GetPacketHeader();
        }

        unsafe public void GetPacketHeader()
        {
            this._clientSendPacketHeader = 
                Helper.BytesToStructure<CLIENT_SEND_PACKET_HEADER>(_buffer, sizeof(PACKET_HEADER));
        }

        public byte[] GetResponsePacket()
        {
            return Helper.StructureToBytes<CLIENT_SEND_PACKET_RESPONSE>(ref this._responsePacket);
        }

        public bool HandleMessage()
        {
            if (this._clientSendPacketHeader.RequestId == 0)
            {
                _logger.Error("Failed to get the client send report code");
                return false;
            }

            switch (this._clientSendPacketHeader.RequestId)
            {
                case (int)CLIENT_SEND_REQUEST_ID.SYSTEM_INFORMATION:
                    HandleClientSendHardwareInformation(this._clientSendPacketHeader);
                    break;
            }

            return true;
        }

        unsafe private void HandleClientSendHardwareInformation(CLIENT_SEND_PACKET_HEADER sendPacketHeader)
        {
            _logger.Information("Handling client send hardware information");

            PACKET_CLIENT_HARDWARE_INFORMATION info = 
                Helper.BytesToStructure<PACKET_CLIENT_HARDWARE_INFORMATION>(
                    _buffer, sizeof(PACKET_HEADER) + sizeof(CLIENT_SEND_PACKET_HEADER));

            _logger.Information("SteamId: {0}, Mobo Serial: {1}, drive serial: {2}", 
                this._packetHeader.steam64_id, 
                info.MotherboardSerialNumber, 
                info.DeviceDriver0Serial);

            /*
             * When a client connects to the server, we will perform the following.
             * 
             * 1. Check if the user exists, 
             *          - if the user doesn't exist we instert them into the database.
             *          - if the user does exist, check if they're banned
             *          - if the user is banned, return a response packet stating the
             *            client may not proceed
             * 2. Next we check if the hardware is banned. We don't care if the hardware doesn't exist
             *    at this point because if it doesn't exist it can't be banned.
             *          - If the hardware is banned, return a cannot proceed packet.
             * 3. Here, we use the method GetUserBySteamId get either get the existing user from the database 
             *    or the newly created user. We then set the User property of the HardwareConfigurationEntity
             *          - This prevents the bug where a new user was always being added with an existing 
             *            user existing with the same steam id.
             * 4. Then we check if the users hardware already exists in the database, and the foreign
             *    UserId references the user by checking if the Steam64Id matches.
             *          - If a hardware configuration already exists, we send a response packet 
             *            allowing the client to continue.
             * 5. If we make it to here, the user is new and the hardware is not banned, so we then create
             *    a new user and a new hardware configuration and insert it into the database and then
             *    return a packet notifying the client can continue.
             */
            using (var context = new ModelContext())
            {
                context.Database.EnsureCreated();

                var user = new UserEntity(context)
                {
                    Steam64Id = this._packetHeader.steam64_id
                };

                if (!user.CheckIfUserExists())
                {
                    _logger.Information("User does not exist in database, creating new user.");
                    user.InsertUser();
                }
                else if (user.CheckIfUserIsBanned())
                {
                    _logger.Information("User is banned, updating response packet to halt client.");
                    SetResponsePacketData(0, sendPacketHeader.RequestId, (int)USER_BAN_REASONS.USER_BAN);
                    return;
                }

                var hardwareConfiguration = new HardwareConfigurationEntity(context)
                {
                    DeviceDrive0Serial = info.DeviceDriver0Serial,
                    MotherboardSerial = info.MotherboardSerialNumber,
                    User = user.GetUserBySteamId(this._packetHeader.steam64_id)
                };

                if (hardwareConfiguration.CheckIfHardwareIsBanned())
                {
                    _logger.Information("User is hardware banned, updating response packet to halt client.");
                    SetResponsePacketData(0, sendPacketHeader.RequestId, (int)USER_BAN_REASONS.HARDWARE_BAN);
                    return;
                }

                if (user.CheckIfUsersHardwareExists())
                {
                    _logger.Information("Users hardware already references the user.");
                    SetResponsePacketData(1, sendPacketHeader.RequestId, 0);
                    return;
                }

                _logger.Information("Users hardware does not existing, inserting hardware.");
                hardwareConfiguration.InsertHardwareConfiguration();
                SetResponsePacketData(1, sendPacketHeader.RequestId, 0);

                context.SaveChanges();
            }
        }

        private void SetResponsePacketData(int canUserProceed, int requestId, int reason)
        {
            this._responsePacket.CanUserProceed = canUserProceed;
            this._responsePacket.RequestId = requestId;
            this._responsePacket.reason = reason;
        }
    }
}
