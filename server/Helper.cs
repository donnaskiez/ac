using Microsoft.AspNetCore.Mvc.Infrastructure;
using Serilog;
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
            catch(Exception ex)
            {
                Log.Information(ex.Message);
                return default(T);
            }
        }

        unsafe public static byte[] StructureToBytes<T>(ref T structure)
        {
            int typeSize = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[typeSize];
            IntPtr ptr = Marshal.AllocHGlobal(typeSize);

            try
            {
                Marshal.StructureToPtr(structure, ptr, true);
                Marshal.Copy(ptr, buffer, 0, typeSize);
                Marshal.FreeHGlobal(ptr);
                return buffer;
            }
            catch (Exception ex)
            {
                Log.Information(ex.Message);
                return null;
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