using Microsoft.Extensions.Logging;
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

        public HardwareConfigurationEntity(ModelContext modelContext)
        {
            _modelContext = modelContext;
        }

        public bool CheckIfHardwareConfigurationExists()
        {
            return _modelContext.HardwareConfiguration.Any(h => h.MotherboardSerial == MotherboardSerial && 
                                                                h.DeviceDrive0Serial == DeviceDrive0Serial);
        }
    }
}
