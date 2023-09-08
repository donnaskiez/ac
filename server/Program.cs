using Serilog;
using server.Database;
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
            
            DatabaseConnection database = new DatabaseConnection();
            database.Open();

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