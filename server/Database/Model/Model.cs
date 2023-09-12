using Microsoft.EntityFrameworkCore;
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
        public virtual ICollection<HardwareConfiguration> HardwareConfigurations { get; set; }
        public virtual ICollection<ReportIllegalHandleOperation> ReportIllegalHandleOperations { get; set; }
    }

    public class HardwareConfiguration
    {
        public int HardwareId { get; set; }
        public virtual User User { get; set; }
        public bool IsBanned { get; set; }
        public string DeviceDrive0Serial { get; set; }
        public string MotherboardSerial { get; set; }
    }

    public class ReportIllegalHandleOperation
    {
        public int ReportId { get; set; }
        public virtual User User { get; set; }
        public int IsKernelHandle { get; set; }
        public uint ProcessId { get; set; }
        public uint ThreadId { get; set; }
        public uint DesiredAccess { get; set; }
        public string ProcessName { get; set; }
    }


}