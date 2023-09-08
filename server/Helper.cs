using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

#pragma warning disable CS8600
#pragma warning disable CS8603

namespace server
{
    public class Helper
    {
        unsafe public static T BytesToStructure<T>(ref byte[] buffer, int offset)
        {
            //int typeSize = Marshal.SizeOf(typeof(T));
            int typeSize = buffer.Length - offset;
            IntPtr ptr = Marshal.AllocHGlobal(typeSize);

            try
            {
                Marshal.Copy(buffer, offset, ptr, typeSize);
                return (T)Marshal.PtrToStructure(ptr, typeof(T));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        unsafe public static string FixedUnsafeBufferToSafeString(ref byte[] buffer, int bufferSize, int offset, int stringSize)
        {
            if (stringSize > bufferSize)
                return null;

            char[] stringBuffer = new char[stringSize];

            for (int i = 0; i < stringSize; i++)
            {
                stringBuffer[i] = (char)buffer[offset + i];
            }

            return new string(stringBuffer);
        }
            
    }
}

#pragma warning restore CS8600
#pragma warning restore CS8603