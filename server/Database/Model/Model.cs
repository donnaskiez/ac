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
        public virtual ICollection<Report> Reports { get; set; }
    }

    public class HardwareConfiguration
    {
        public int HardwareId { get; set; }
        public virtual User User { get; set; }
        public bool IsBanned { get; set; }
        public string DeviceDrive0Serial { get; set; }
        public string MotherboardSerial { get; set; }
    }

    public class Report
    {
        public int ReportId { get; set; }
        public virtual User User { get; set; }
        public int ReportCode { get; set; }
        public virtual ICollection<ReportTypeIllegalHandleOperation> ReportTypeIllegalHandleOperations { get; set; }
        public virtual ICollection<ReportTypeStartAddress> ReportTypeStartAddresses { get; set; }
        public virtual ICollection<ReportTypePageProtection> ReportTypePageProtections { get; set; }
        public virtual ICollection<ReportTypePatternScan> ReportTypePatternScans { get; set; }
        public virtual ICollection<ReportTypeNmiCallback> ReportTypeNmiCallbacks { get; set; }
        public virtual ICollection<ReportTypeSystemModuleValidation> ReportTypeSystemModuleValidations { get; set; }
    }

    public class ReportTypeIllegalHandleOperation
    {
        public int ReportNumber { get; set; }
        public virtual Report Report { get; set; }
        public int IsKernelHandle { get; set; }
        public uint ProcessId { get; set; }
        public uint ThreadId { get; set; }
        public uint DesiredAccess { get; set; }
        public string ProcessName { get; set; }
    }

    public class ReportTypeStartAddress
    {
        public int ReportNumber { get; set; }
        public virtual Report Report { get; set; }
        public int ThreadId { get; set; }
        public long ThreadStartAddress { get; set; }
    }

    public class ReportTypePageProtection
    {
        public virtual Report Report { get; set; }
        public int ReportNumber { get; set; }
        public ulong PageBaseAddress { get; set; }
        public long AllocationProtection { get; set; }
        public long AllocationState { get; set; }
        public long AllocationType { get; set; }
    }

    public class ReportTypePatternScan
    {
        public virtual Report Report { get; set; }
        public int ReportNumber { get; set; }
        public int SignatureId { get; set; }
        public ulong Address { get; set; }
    }

    public class ReportTypeNmiCallback
    {
        public virtual Report Report { get; set; }
        public int ReportNumber { get; set; }
        public int WereNmisDisabled { get; set; }
        public ulong KThreadAddress { get; set; }
        public ulong InvalidRip { get; set; }
    }

    public class ReportTypeSystemModuleValidation
    {
        public virtual Report Report { get; set; }
        public int ReportNumber { get; set; }
        public int ReportType { get; set; }
        public long DriverBaseAddress { get; set; }
        public long DriverSize { get; set; }
        public string ModuleName { get; set; }
    }
}