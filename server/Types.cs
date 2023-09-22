using Org.BouncyCastle.Utilities;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace server
{
    namespace Types
    {
        namespace ClientSend
        {
            struct CLIENT_SEND_PACKET_HEADER
            {
                public int RequestId;
                public int PacketSize;
            };

            public enum USER_BAN_REASONS
            {
                HARDWARE_BAN = 10,
                USER_BAN = 20
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public unsafe struct PACKET_CLIENT_HARDWARE_INFORMATION
            {
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
                public string MotherboardSerialNumber;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
                public string DeviceDriver0Serial;
            }
        }

        namespace ClientReport
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public unsafe struct PROCESS_MODULE_INTEGRITY_CHECK_FAILURE
            {
                public int ReportCode;
                public UInt64 ModuleBaseAddress;
                public int ModuleSize;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
                public string ModuleName;
            }

            public struct PROCESS_THREAD_START_FAILURE
            {
                public int ReportCode;
                public int ThreadId;
                public long StartAddress;
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

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public unsafe struct MODULE_VALIDATION_FAILURE
            {
                public int ReportCode;
                public int ReportType;
                public long DriverBaseAddress;
                public long DriverSize;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
                public string ModuleName;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public unsafe struct OPEN_HANDLE_FAILURE
            {
                public int ReportCode;
                public int IsKernelHandle;
                public uint ProcessId;
                public uint ThreadId;
                public uint DesiredAccess;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
                public string ProcessName;

            }

            public struct INVALID_PROCESS_ALLOCATION_FAILURE
            {
                public int ReportCode;
                public byte[] ProcessStructure;
            }

            public struct HIDDEN_SYSTEM_THREAD_FAILURE
            {
                public int ReportCode;
                public int FoundInKThreadList;
                public int FoundInPspCidTable;
                public long ThreadAddress;
                public int ThreadId;
                public byte[] ThreadStructure;
            }

            public struct ATTACH_PROCESS_FAILURE
            {
                public int ReportCode;
                public int ThreadId;
                public long ThreadAddress;
            }
        }
    }
}
