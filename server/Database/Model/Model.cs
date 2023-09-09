using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

namespace server.Database.Model
{
    public class User
    {
        public int UserId { get; set; }
        public ulong Steam64Id { get; set; }
        public bool IsBanned { get; set; }
        public ICollection<HardwareConfiguration> HardwareConfigurations { get; set; }
    }

    public class HardwareConfiguration
    {
        public int HardwareId { get; set; }
        public int UserId { get; set; }
        public virtual User User { get; set; }
        public bool IsBanned { get; set; }
        public string DeviceDrive0Serial { get; set; }
        public string MotherboardSerial { get; set; }
    }
}
