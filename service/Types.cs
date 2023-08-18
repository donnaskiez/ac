using System;
using System.Collections.Generic;
using System.Linq;
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
    }
}
