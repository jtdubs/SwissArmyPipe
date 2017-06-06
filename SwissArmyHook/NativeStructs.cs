using System;
using System.Runtime.InteropServices;

namespace SwissArmyHook
{
    /// <summary>
    /// OVERLAPPED_ENTRY structure used by GetQueuedCompletionStatusEx
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeOverlappedEntry
    {
        public IntPtr lpCompletionKey;
        public IntPtr lpOverlapped;
        public IntPtr Internal;
        public uint dwNumberOfBytesTransferred;
    }

    /// <summary>
    /// PROCESS_INFORMATION structure used by CreateProcess and friends
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessID;
        public uint dwThreadId;
    }
}
