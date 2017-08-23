using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    public SafeProcessHandle()
        : base(true)
    {
    }

    public SafeProcessHandle(IntPtr handle)
        : base(true)
    {
        base.SetHandle(handle);
    }

    public void InitialSetHandle(IntPtr handlePtr)
    {
        handle = handlePtr;
    }

    protected override bool ReleaseHandle()
    {
        return CloseHandle(handle);
    }
}