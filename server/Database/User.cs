using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database
{
    public class User : DatabaseConnection
    {
        private ILogger _logger;

        public User(ILogger<User> logger)
        {
            _logger = logger;
        }
        
    }
}
