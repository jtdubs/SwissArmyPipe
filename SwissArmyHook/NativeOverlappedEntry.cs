using System;
using System.Runtime.InteropServices;

namespace SwissArmyHook
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeOverlappedEntry
    {
        public IntPtr lpCompletionKey;
        public IntPtr lpOverlapped;
        public IntPtr Internal;
        public uint dwNumberOfBytesTransferred;
    }
}
