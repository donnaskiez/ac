using Serilog;
using server.Database;
using server.Database.Entity;
using server.Database.Model;
using System.Configuration;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Text;

namespace server
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            using var logger = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();
            
            using (var context = new ModelContext())
            {
                context.Database.EnsureCreated();

                Database.Entity.UserEntity user = new Database.Entity.UserEntity(logger, context);

                user.IsBanned = false;
                user.Steam64Id = 123123123;

                user.HardwareConfigurationEntity = new HardwareConfigurationEntity(context);
                user.HardwareConfigurationEntity.MotherboardSerial = 987654321;
                user.HardwareConfigurationEntity.DeviceDrive0Serial = 123456789;

                if (user.IsUsersHardwareBanned())
                {
                    logger.Information("Users hardware is banned");
                }
                else
                {
                    if (user.CheckIfUserExists())
                    {
                        if (user.CheckIfUserIsBanned())
                        {
                            logger.Information("User is banned");
                        }
                        else
                        {
                            logger.Information("User is not banned");
                        }
                    }
                    else
                    {
                        logger.Information("User does not exist");

                        user.InsertUser();
                    }
                }

                await context.SaveChangesAsync();
            }

            Server server = new Server(logger);
            await server.Listen();
        }
    }
}

/*namespace server
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            await Program.Listen();
        }

        public static async Task Listen()
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Any, 8888);
            TcpListener listener = new(ipEndPoint);

            try
            {
                listener.Start();

                using TcpClient handler = await listener.AcceptTcpClientAsync();
                await using NetworkStream stream = handler.GetStream();

                stream.BeginRead(new byte[1024], 0, 1024, Callback, null);

                var message = $"📅 {DateTime.Now} 🕛";
                var dateTimeBytes = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(dateTimeBytes);
            }
            finally
            {
                listener.Stop();
            }
        }

        public static void Callback(IAsyncResult ar)
        {
            Console.WriteLine("Is ocmpleted: {0}", ar.IsCompleted);
        }
    }
}*/