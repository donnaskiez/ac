using Serilog;
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
        namespace Receive
        {
            struct PIPE_PACKET_SEND_EXTENSION_HEADER
            {
                public int request_id;
                public int current_packet_number;
                public int total_incoming_packet_count;
                public long packet_size;
                public long total_incoming_packet_size;
            };
        }

        namespace Reports
        {
            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct MODULE_VERIFICATION_CHECKSUM_FAILURE
            {
                public int ReportCode;
                public UInt64 ModuleBaseAddress;
                public UInt64 ModuleSize;
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

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct OPEN_HANDLE_FAILURE_REPORT
            {
                public int ReportCode;
                public int IsKernelHandle;
                public uint ProcessId;
                public uint ThreadId;
                public uint DesiredAccess;
                public fixed char ProcessName[64];

            }
        }
    }
}
