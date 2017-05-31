using System;
using EasyHook;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections.Concurrent;

namespace SwissArmyHook
{
    public class InjectionEntryPoint : IEntryPoint
    {
        public InjectionEntryPoint(RemoteHooking.IContext context, string channelName)
        {
            server = RemoteHooking.IpcConnectClient<ServerInterface>(channelName);
            server.Ping();
        }

        public void Run(RemoteHooking.IContext context, string channelName)
        {
            server.IsInstalled(RemoteHooking.GetCurrentProcessId());

            var createFileHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
               new CreateFile_Delegate(CreateFile_Hook),
               this);

            var createNamedPipeHook = EasyHook.LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "CreateNamedPipeW"),
               new CreateNamedPipe_Delegate(CreateNamedPipe_Hook),
               this);

            var createIoCompletionPortHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "CreateIoCompletionPort"),
               new CreateIoCompletionPort_Delegate(CreateIoCompletionPort_Hook),
               this);

            var getOverlappedResultHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "GetOverlappedResult"),
               new GetOverlappedResult_Delegate(GetOverlappedResult_Hook),
               this);

            var getQueuedCompletionStatusHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "GetQueuedCompletionStatus"),
               new GetQueuedCompletionStatus_Delegate(GetQueuedCompletionStatus_Hook),
               this);

            var getQueuedCompletionStatusExHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "GetQueuedCompletionStatusEx"),
               new GetQueuedCompletionStatusEx_Delegate(GetQueuedCompletionStatusEx_Hook),
               this);

            var readFileHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
               new ReadFile_Delegate(ReadFile_Hook),
               this);

            var writeFileHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "WriteFile"),
               new WriteFile_Delegate(WriteFile_Hook),
               this);

            var readFileExHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "ReadFileEx"),
               new ReadFileEx_Delegate(ReadFileEx_Hook),
               this);

            var writeFileExHook = LocalHook.Create(
               LocalHook.GetProcAddress("kernel32.dll", "WriteFileEx"),
               new WriteFileEx_Delegate(WriteFileEx_Hook),
               this);

            createFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            createNamedPipeHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            createIoCompletionPortHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            getOverlappedResultHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            getQueuedCompletionStatusHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            getQueuedCompletionStatusExHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            readFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            writeFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            readFileExHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            writeFileExHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            server.ReportMessage("Installed!");
            RemoteHooking.WakeUpProcess();

            try
            {
                while (true)
                {
                    string item;
                    if (queue.TryTake(out item, 1000))
                        server.ReportMessage(item);
                    else
                        server.Ping();
                }
            }
            catch
            {
            }

            createFileHook.Dispose();
            createNamedPipeHook.Dispose();
            createIoCompletionPortHook.Dispose();
            getOverlappedResultHook.Dispose();
            getQueuedCompletionStatusHook.Dispose();
            getQueuedCompletionStatusExHook.Dispose();
            readFileHook.Dispose();
            writeFileHook.Dispose();
            readFileExHook.Dispose();
            writeFileExHook.Dispose();

            LocalHook.Release();
        }

        #region CreateFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateFileW(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateFile_Delegate(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);

        private IntPtr CreateFile_Hook(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile)
        {
            var handle = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
          
            try
            {
                if (lpFileName.StartsWith(@"\\.\pipe\", StringComparison.InvariantCultureIgnoreCase))
                {
                    queue.Add(String.Format("CreateFile(\"{0}\") = {1:X08}", lpFileName, handle.ToInt32()));
                }
            }
            catch
            {
            }

            return handle;
        }
        #endregion

        #region CreateNamedPipe
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateNamedPipeW(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateNamedPipe_Delegate(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes);

        private IntPtr CreateNamedPipe_Hook(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes)
        {
            var handle = CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);

            try
            {
                queue.Add(String.Format("CreateNamedPipe(\"{0}\") = {1:X08}", lpName, handle.ToInt32()));
            }
            catch
            {
            }

            return handle;
        }
        #endregion

        #region CreateIoCompletionPort
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateIoCompletionPort(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateIoCompletionPort_Delegate(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads);

        private IntPtr CreateIoCompletionPort_Hook(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads)
        {
            var result = CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);

            try
            {
                queue.Add(String.Format("CreateIoCompletionPort()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region GetOverlappedResult
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetOverlappedResult(IntPtr hFile, ref System.Threading.NativeOverlapped lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetOverlappedResult_Delegate(IntPtr hFile, ref System.Threading.NativeOverlapped lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

        private bool GetOverlappedResult_Hook(IntPtr hFile, ref System.Threading.NativeOverlapped lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait)
        {
            var result = GetOverlappedResult(hFile, ref lpOverlapped, out lpNumberOfBytesTransferred, bWait);

            try
            {
                queue.Add(String.Format("GetOverlappedResult()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region GetQueuedCompletionStatus
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetQueuedCompletionStatus(IntPtr CompletionPort, out uint lpNumberOfBytes, out IntPtr lpCompletionKey, out NativeOverlapped lpOverlapped, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetQueuedCompletionStatus_Delegate(IntPtr CompletionPort, out uint lpNumberOfBytes, out IntPtr lpCompletionKey, out NativeOverlapped lpOverlapped, uint dwMilliseconds);

        private bool GetQueuedCompletionStatus_Hook(IntPtr CompletionPort, out uint lpNumberOfBytes, out IntPtr lpCompletionKey, out NativeOverlapped lpOverlapped, uint dwMilliseconds)
        {
            var result = GetQueuedCompletionStatus(CompletionPort, out lpNumberOfBytes, out lpCompletionKey, out lpOverlapped, dwMilliseconds);

            try
            {
                queue.Add(String.Format("GetQueuedCompletionStatus()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region GetQueuedCompletionStatusEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetQueuedCompletionStatusEx(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetQueuedCompletionStatusEx_Delegate(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable);

        private bool GetQueuedCompletionStatusEx_Hook(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable)
        {
            var result = GetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries, ulCount, out ulNumEntriesRemoved, dwMilliseconds, fAlertable);

            try
            {
                queue.Add(String.Format("GetQueuedCompletionStatusEx()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region ReadFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool ReadFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        private bool ReadFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            var result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

            try
            {
                queue.Add(String.Format("ReadFile()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region WriteFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool WriteFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        private bool WriteFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped)
        {
            var result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);

            try
            {
                queue.Add(String.Format("WriteFile()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region ReadFileEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadFileEx(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool ReadFileEx_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        private bool ReadFileEx_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine)
        {
            var result = ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);

            try
            {
                queue.Add(String.Format("ReadFileEx()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        #region WriteFileEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteFileEx(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool WriteFileEx_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        private bool WriteFileEx_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine)
        {
            var result = WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);

            try
            {
                queue.Add(String.Format("WriteFileEx()"));
            }
            catch
            {
            }

            return result;
        }
        #endregion

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        private ServerInterface server = null;
        BlockingCollection<string> queue = new BlockingCollection<string>();
    }
}