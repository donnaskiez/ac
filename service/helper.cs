using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

#pragma warning disable CS8600
#pragma warning disable CS8603

namespace service
{
    public class Helper
    {
        unsafe public static T BytesToStructure<T>(ref byte[] buffer)
        {
            int typeSize = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(typeSize);

            try
            {
                Marshal.Copy(buffer, 0, ptr, typeSize);
                return (T)Marshal.PtrToStructure(ptr, typeof(T));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}

#pragma warning restore CS8600
#pragma warning restore CS8603