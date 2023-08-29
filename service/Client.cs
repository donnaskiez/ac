using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Serilog;

namespace service
{
    public class Client
    {
        public static async Task SendToServer()
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8888);

            using TcpClient client = new();

            await client.ConnectAsync(ipEndPoint);
            await using NetworkStream stream = client.GetStream();

            var testMessage = "Hello from client";

            stream.BeginWrite(Encoding.UTF8.GetBytes(testMessage), 0, testMessage.Length, Callback, null);

            byte[] buffer = new byte[1024];
            int received = await stream.ReadAsync(buffer);

            var message = Encoding.UTF8.GetString(buffer, 0, received);
            Console.WriteLine($"Message received: \"{message}\"");

            while (true)
            {

            }
        }

        private static void Callback(IAsyncResult ar)
        {
            Log.Information("Sent message lolz");
        }

    }
}