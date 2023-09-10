using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using server.Database.Model;
using System.Reflection.Metadata.Ecma335;
using Microsoft.EntityFrameworkCore;

namespace server.Database.Entity
{
    public class HardwareConfigurationEntity : HardwareConfiguration
    {
        private readonly ModelContext _modelContext;
        public UserEntity UserEntity { get; set; }

        public HardwareConfigurationEntity(ModelContext modelContext)
        {
            UserEntity = new UserEntity(modelContext);
            _modelContext = modelContext;
        }

        public bool CheckIfHardwareIsBanned()
        {
            return _modelContext.HardwareConfiguration.Any(
                        h => h.MotherboardSerial == MotherboardSerial &&
                             h.DeviceDrive0Serial == DeviceDrive0Serial &&
                             h.IsBanned);
        }

        public bool CheckIfHardwareExists()
        {
            return _modelContext.HardwareConfiguration.Any(
                                       h => h.MotherboardSerial == MotherboardSerial &&
                                            h.DeviceDrive0Serial == DeviceDrive0Serial);
        }

        public void InsertHardwareConfiguration()
        {
            _modelContext.HardwareConfiguration.Add(this);
        }
    }
}
