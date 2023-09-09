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

            Server server = new Server(logger);
            await server.Listen();
        }
    }
}