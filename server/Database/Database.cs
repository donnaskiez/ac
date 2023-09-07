using Microsoft.AspNetCore.Routing;
using MySql.Data.MySqlClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database
{
    public class DatabaseConnection : IDisposable
    {
        private MySqlConnection _connection;

        public DatabaseConnection()
        {
            string connectionString = @"server=localhost;userid=root;password=root;database=ac_db";
            _connection = new MySqlConnection(connectionString);
        }

        public void Open()
        {
            try
            {
                _connection.Open();
            }
            catch(MySqlException ex)
            {
                throw new DatabaseConnectionException("Cannot connect to server.", ex);
            }
        }

        public void Close()
        {
            try
            {
                _connection.Close();
            }
            catch(MySqlException ex)
            {
                throw new DatabaseConnectionException("Cannot disconnect from server.", ex);
            }
        }

        public void Dispose()
        {
            Close();
        }
    }

    public class DatabaseConnectionException : Exception
    {
        internal DatabaseConnectionException(string message, MySqlException inner) : base(message, inner)
        {
        }

        public int ErrorCode => ((MySqlException)InnerException).ErrorCode;
    }
}
