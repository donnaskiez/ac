using Serilog;
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
        unsafe public static T BytesToStructure<T>(byte[] buffer, int offset)
        {
            int typeSize = Marshal.SizeOf(typeof(T));

            if (buffer.Length == 0)
                return default(T);

            IntPtr ptr = Marshal.AllocHGlobal(typeSize);

            try
            {
                Marshal.Copy(buffer, offset, ptr, typeSize);
                T result = (T)Marshal.PtrToStructure(ptr, typeof(T));
                Marshal.FreeHGlobal(ptr);
                return result;
            }
            catch (Exception ex)
            {
                Log.Information(ex.Message);
                return default(T);
            }
        }
    }
}

#pragma warning restore CS8600
#pragma warning restore CS8603