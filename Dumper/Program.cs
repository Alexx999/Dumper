using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;

namespace Dumper
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );
        

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess,
            IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);


        public static bool TryParse(string str, out long value)
        {

            return long.TryParse(str, NumberStyles.Any, CultureInfo.InvariantCulture, out value) ||
                   TryParseHex(str, out value);
        }
        public static bool TryParseHex(string str, out long value)
        {
            value = 0;
            if (str.Length < 3) return false;
            if (!str.StartsWith("0x")) return false;

            return long.TryParse(str.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Wrong argument count.\nUsage:\ndumper.exe <debugged process id or name> <memory_start_addr> <memory_length>");
                return;
            }

            if (!TryParse(args[1], out var address))
            {
                Console.WriteLine($"Bad address value {args[1]}");
                return;
            }

            if (!TryParse(args[2], out var length))
            {
                Console.WriteLine($"Bad length value {args[2]}");
                return;
            }

            if (!int.TryParse(args[0], out var processId))
            {
                var processName = args[0];
                var process = Process.GetProcessesByName(processName);
                if (process.Length == 0)
                {
                    Console.WriteLine($"Process {processName} not found");
                    return;
                }
                if (process.Length > 1)
                {
                    Console.WriteLine($"Found more than one instance of process with name {processName}");
                    return;
                }
                processId = process.Single().Id;
            }

            using (var process = OpenProcess(ProcessAccessFlags.VirtualMemoryRead, false, processId))
            {
                if (process.IsInvalid)
                {
                    Console.WriteLine($"Opening process {processId} failed with error {Marshal.GetLastWin32Error()}");
                    return;
                }

                var outFileName = $"{args[0]}-{args[1]}-{args[2]}";

                outFileName = GetNextFreeName(outFileName, ".dmp");

                Console.WriteLine($"Saving contents of process {processId} to {outFileName}");

                try
                {
                    Dump(process, outFileName, new IntPtr(address), new IntPtr(length));
                    Console.WriteLine("Done");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Writing file failed with exception {e}");
                }
            }
        }

        private static void Dump(SafeProcessHandle process, string outFileName, IntPtr address, IntPtr length)
        {
            using (var file = File.Create(outFileName))
            using (var mmf = MemoryMappedFile.CreateFromFile(file, null, length.ToInt64(), MemoryMappedFileAccess.ReadWrite, null, HandleInheritability.None, false))
            using (var accessor = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Write))
            {
                var buffer = (SafeBuffer)accessor.SafeMemoryMappedViewHandle;
                var ptr = buffer.DangerousGetHandle();
                if (!ReadProcessMemory(process.DangerousGetHandle(), address, ptr, length, out var read))
                {
                    Console.WriteLine($"Reading process memory failed with error {Marshal.GetLastWin32Error()}");
                }
                if (read != length)
                {
                    Console.WriteLine($"Data was read partially - {read.ToInt64()} bytes out of {length.ToInt64()} bytes requested");
                    file.SetLength(read.ToInt64());
                }
            }
        }

        private static string GetNextFreeName(string outFileName, string ext)
        {
            var currName = outFileName;
            var counter = 0;
            while (File.Exists(currName + ext))
            {
                counter++;
                currName = $"{outFileName}({counter})";
            }
            return currName + ext;
        }
    }
}
