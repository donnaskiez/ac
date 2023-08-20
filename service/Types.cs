using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace service
{
    namespace Types
    {
        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct MODULE_VERIFICATION_CHECKSUM_FAILURE
        {
            [FieldOffset(0)]
            public int ReportCode;
            [FieldOffset(0)]
            public UInt64 ModuleBaseAddress;
            [FieldOffset(0)]
            public UInt64 ModuleSize;
            [FieldOffset(0)]
            public fixed char ModuleName[512];
        }

        public struct PROCESS_THREAD_START_FAILURE
        {
            public int ReportCode;
            public long ThreadId;
            public UInt64 StartAddress;
        }

        public struct PAGE_PROTECTION_FAILURE
        {
            public int ReportCode;
            public UInt64 PageBaseAddress;
            public long AllocationProtection;
            public long AllocationState;
            public long AllocationType;
        }

        public struct PATTERN_SCAN_FAILURE
        {
            public int ReportCode;
            public int SignatureId;
            public UInt64 Address;
        }

        public struct NMI_CALLBACK_FAILURE
        {
            public int ReportCode;
            public int WereNmisDisabled;
            public UInt64 KThreadAddress;
            public UInt64 InvalidRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct MODULE_VALIDATION_FAILURE
        {
            public int ReportCode;
            public int ReportType;
            public long DriverBaseAddress;
            public long DriverSize;
            public fixed char ModuleName[128];
        }
    }
}
