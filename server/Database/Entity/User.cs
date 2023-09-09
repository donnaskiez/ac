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
        private readonly ILogger _logger;
        private readonly ModelContext _modelContext;
        public HardwareConfigurationEntity HardwareConfigurationEntity { get; set; }

        public UserEntity(ILogger logger, ModelContext modelContext)
        {
            _logger = logger;
            _modelContext = modelContext;
            HardwareConfigurationEntity = new HardwareConfigurationEntity(_modelContext);
        }

        public bool CheckIfUserExists()
        {
            return _modelContext.Users.Any(u => u.Steam64Id == Steam64Id);
        }

        public bool CheckIfUserIsBanned()
        {
            return _modelContext.Users.Any(u => u.Steam64Id == Steam64Id && u.IsBanned);
        }

        public bool IsUsersHardwareBanned()
        {
            HardwareConfigurationEntity hwConfig = new HardwareConfigurationEntity(_modelContext);
            hwConfig.MotherboardSerial = HardwareConfigurationEntity.MotherboardSerial;
            hwConfig.DeviceDrive0Serial = HardwareConfigurationEntity.DeviceDrive0Serial;

            return hwConfig.CheckIfHardwareConfigurationExists() && hwConfig.IsBanned;
        }

        public void InsertUser()
        {
            _modelContext.Users.Add(this);
        }
    }
}
