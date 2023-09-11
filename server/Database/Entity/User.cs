using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using server.Database.Model;
using Serilog;

namespace server.Database.Entity
{
    public class UserEntity : User
    {
        private readonly ModelContext _modelContext;

        public UserEntity(ModelContext modelContext)
        {
            _modelContext = modelContext;
        }

        public bool CheckIfUserExists()
        {
            return _modelContext.Users.Any(u => u.Steam64Id == Steam64Id);
        }

        public bool CheckIfUserIsBanned()
        {
            return _modelContext.Users.Any(u => u.Steam64Id == Steam64Id && u.IsBanned);
        }

        public User GetUserBySteamId(ulong steamId)
        {
            return _modelContext.Users.First(u => u.Steam64Id == steamId);
        }

        public bool CheckIfUsersHardwareExists()
        {
            List<HardwareConfiguration> hardwareConfigurations = _modelContext.HardwareConfiguration
                .Where(h => h.User.Steam64Id == Steam64Id).ToList();

            return hardwareConfigurations.Count > 0;
        }

        public void InsertUser()
        {
            _modelContext.Users.Add(this);
        }
    }
}
