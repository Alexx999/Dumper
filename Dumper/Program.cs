using System;
using System.Collections.Generic;
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
        All = 0x001FFFFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        SetSessionId = 0x00000004,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        SuspendResume = 0x00000800,
        QueryLimitedInformation = 0x00001000,
        SetLimitedInformation = 0x00002000,
        Synchronize = 0x00100000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400
    }

    public enum MemoryState : uint
    {
        Commit = 0x1000,
        Free = 0x10000,
        Reserve = 0x2000
    }

    public enum MemoryType : uint
    {
        Image = 0x1000000,
        Mapped = 0x40000,
        Private = 0x20000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation32
    {
        public int BaseAddress;
        public int AllocationBase;
        public MemoryProtection AllocationProtect;
        public int RegionSize;
        public MemoryState State;
        public MemoryProtection Protect;
        public MemoryType Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation64
    {
        public long BaseAddress;
        public long AllocationBase;
        public MemoryProtection AllocationProtect;
        public long RegionSize;
        public MemoryState State;
        public MemoryProtection Protect;
        public MemoryType Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryProtection AllocationProtect;
        public UIntPtr RegionSize;
        public MemoryState State;
        public MemoryProtection Protect;
        public MemoryType Type;
    }

    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );

        [DllImport("ntdll.dll", SetLastError = false)]
        public static extern IntPtr NtSuspendProcess(IntPtr ProcessHandle);


        [DllImport("ntdll.dll", SetLastError = false)]
        public static extern IntPtr NtResumeProcess(IntPtr ProcessHandle);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess,
            IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

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
            if (args.Length != 3 && args.Length != 4)
            {
                Console.WriteLine("Wrong argument count.\nUsage:\ndumper.exe <debugged process id or name> <memory_start_addr> <memory_length> (-unprotect)");
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

            var unprotect = args.Length > 3 && args[3] == "-unprotect";

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

            var rights = ProcessAccessFlags.VirtualMemoryRead;
            if (unprotect)
            {
                rights |= ProcessAccessFlags.SuspendResume | ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryOperation;
            }

            using (var process = OpenProcess(rights, false, processId))
            {
                if (process.IsInvalid)
                {
                    Console.WriteLine($"Opening process {processId} failed with error {Marshal.GetLastWin32Error()}");
                    return;
                }

                var outFileName = $"{args[0]}-{args[1]}-{args[2]}";

                outFileName = GetNextFreeName(outFileName, ".dmp");

                Console.WriteLine($"Saving contents of process {processId} to {outFileName}");

                List<MemBlock> unprotected = null;

                if (unprotect)
                {
                    NtSuspendProcess(process.DangerousGetHandle());

                    try
                    {
                        Console.WriteLine("Unprotecting");
                        unprotected = Unprotect(process, new IntPtr(address), new IntPtr(length));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Unprotecting failed with exception {e}");
                        return;
                    }
                }

                try
                {
                    Dump(process, outFileName, new IntPtr(address), new IntPtr(length), unprotect);
                    Console.WriteLine("Done");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Writing file failed with exception {e}");
                }


                if (unprotect)
                {
                    Protect(process, unprotected);
                    NtResumeProcess(process.DangerousGetHandle());
                }
            }
        }

        private static void Protect(SafeProcessHandle process, List<MemBlock> unprotected)
        {
            foreach (var block in unprotected)
            {
                VirtualProtectEx(process.DangerousGetHandle(), block.Address, block.Size, block.OriginalProtection, out _);
            }
        }

        private static List<MemBlock> Unprotect(SafeProcessHandle process, IntPtr address, IntPtr length)
        {
            var page = Environment.SystemPageSize;

            var result = new List<MemBlock>();

            var baseAddr = (address.ToInt64() / page) * page;

            var totalLen = 0UL;

            var currAddr = baseAddr;

            while (true)
            {
                if (VirtualQueryEx(process.DangerousGetHandle(), new IntPtr(currAddr), out var info,
                        Marshal.SizeOf(typeof(MemoryBasicInformation))) == 0)
                {
                    throw new Exception($"Unable to query memory at 0x{currAddr:X16}, error 0x{Marshal.GetLastWin32Error():X8}");
                }

                totalLen += info.RegionSize.ToUInt64();

                if (!IsReadable(info.Protect))
                {
                    if (!VirtualProtectEx(process.DangerousGetHandle(), info.BaseAddress, info.RegionSize, MemoryProtection.ReadOnly, out var origProt))
                    {
                        throw new Exception($"Unable to unprotect memory at 0x{info.BaseAddress.ToInt64():X16}, error 0x{Marshal.GetLastWin32Error():X8}");
                    }
                    result.Add(new MemBlock { Address = info.BaseAddress, Size = info.RegionSize, OriginalProtection = origProt });
                }


                if (totalLen >= (ulong) length.ToInt64())
                {
                    break;
                }
            }

            return result;
        }

        private static bool IsReadable(MemoryProtection protect)
        {
            return protect.HasFlag(MemoryProtection.ReadOnly) || protect.HasFlag(MemoryProtection.ReadWrite) ||
                   protect.HasFlag(MemoryProtection.ExecuteRead) || protect.HasFlag(MemoryProtection.ExecuteReadWrite);
        }

        private static void Dump(SafeProcessHandle process, string outFileName, IntPtr address, IntPtr length, bool unprotect)
        {
            using (var file = File.Create(outFileName))
            {
                IntPtr read;
                using (var mmf = MemoryMappedFile.CreateFromFile(file, null, length.ToInt64(), MemoryMappedFileAccess.ReadWrite, null, HandleInheritability.None, true))
                using (var accessor = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Write))
                {
                    var buffer = (SafeBuffer) accessor.SafeMemoryMappedViewHandle;
                    var ptr = buffer.DangerousGetHandle();
                    if (!ReadProcessMemory(process.DangerousGetHandle(), address, ptr, length, out read))
                    {
                        var error = Marshal.GetLastWin32Error();
                        Console.WriteLine($"Reading process memory failed with error 0x{error:8X}");
                        if (error == 299 && !unprotect)
                        {
                            Console.WriteLine("You can try -unprotect option");
                        }
                    }
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

    internal struct MemBlock
    {
        public IntPtr Address { get; set; }
        public MemoryProtection OriginalProtection { get; set; }
        public UIntPtr Size { get; set; }
    }
}
