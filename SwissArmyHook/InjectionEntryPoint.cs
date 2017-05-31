using System;
using EasyHook;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

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
                // if a pipe was successfully opened
                if (handle.ToInt32() != -1 && lpFileName.StartsWith(@"\\.\pipe\", StringComparison.InvariantCultureIgnoreCase))
                {
                    // map the handle to the original pipe name and create a pcap file
                    pipeHandleToName[handle] = lpFileName;
                    pcapWriters[handle] = new PCapNGWriter(new BinaryWriter(File.Create(String.Format("client-{0}.pcapng", Path.GetFileName(lpFileName)))));
                    queue.Add(String.Format("Handle({1:X08}) = Client(\"{0}\")", lpFileName, handle.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("CreateFile Error: {0}", ex.Message));
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
                // if a pipe was successfully opened
                if (handle.ToInt32() != -1)
                {
                    // map the handle to the original pipe name and create a pcap file
                    pipeHandleToName[handle] = lpName;
                    pcapWriters[handle] = new PCapNGWriter(new BinaryWriter(File.Create(String.Format("server-{0}.pcapng", Path.GetFileName(lpName)))));
                    queue.Add(String.Format("Handle({1:X08}) = Server(\"{0}\")", lpName, handle.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("CreateNamedPipe Error: {0}", ex.Message));
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
                // if a completion port was successfully associated with an open pipe
                if (pipeHandleToName.ContainsKey(FileHandle) && result.ToInt32() != 0)
                {
                    // associate completion port/key with pipe handle, 
                    ioPortToHandles.AddOrUpdate(result, new ConcurrentBag<IntPtr>(new IntPtr[] { FileHandle }), (n, b) => { b.Add(n); return b; });
                    completionKeyToHandle.AddOrUpdate(CompletionKey, k => FileHandle, (k, h) => FileHandle);
                    queue.Add(String.Format("Port({0:X08}) = Handle({1:X08}) & Key({2:X08})", result.ToInt32(), FileHandle.ToInt32(), CompletionKey.ToUInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("CreateIoCompletionPort Error: {0}", ex.Message));
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
                // if the read was for a pipe
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    // if the read succeeded
                    if (result)
                    {
                        // show the data that was read
                        byte[] buffer = new byte[lpNumberOfBytesRead];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesRead);
                        OnDataReceived(hFile, buffer);
                        queue.Add(String.Format("Read(Handle({0:X08}), #{1}) -> [{2}]", hFile.ToInt32(), nNumberOfBytesToRead, BitConverter.ToString(buffer).Replace("-", "")));
                    }
                    // if the read is async (overlapped)
                    else if (lpOverlapped.ToInt32() != 0 && Marshal.GetLastWin32Error() == 997 /* ERROR_IO_PENDING */)
                    {
                        // associate the overlapped structure w/ the buffer
                        overlappedToBuffer.AddOrUpdate(lpOverlapped, lpBuffer, (a, b) => lpBuffer);
                        overlappedToDirection.AddOrUpdate(lpOverlapped, false, (a, b) => false);
                        queue.Add(String.Format("Read(Handle({0:X08}), #{1}) -> Overlapped({2:X08})", hFile.ToInt32(), nNumberOfBytesToRead, lpOverlapped.ToInt32()));
                    }
                    // otherwise, something unexpected happened
                    else
                    {
                        queue.Add(String.Format("Read(Handle({0:X08}), @{1}) = !!", hFile.ToInt32(), nNumberOfBytesToRead));
                    }
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("ReadFile Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region WriteFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool WriteFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped);

        private bool WriteFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped)
        {
            var result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

            try
            {
                // if the write was for a pipe
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    // if the write succeeded
                    if (result)
                    {
                        // show the data that was written
                        int count = lpNumberOfBytesWritten == IntPtr.Zero ? (int)nNumberOfBytesToWrite : Marshal.ReadInt32(lpNumberOfBytesWritten); // uint -> int !!
                        byte[] buffer = new byte[count];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)count);
                        OnDataSent(hFile, buffer);
                        queue.Add(String.Format("Write(Handle({0:X08}), #{1}) -> [{2}]", hFile.ToInt32(), nNumberOfBytesToWrite, BitConverter.ToString(buffer).Replace("-", "")));
                    }
                    // if the read is async (overlapped)
                    else if (lpOverlapped.ToInt32() != 0 && Marshal.GetLastWin32Error() == 997 /* ERROR_IO_PENDING */)
                    {
                        // associate the overlapped structure w/ the buffer
                        overlappedToBuffer.AddOrUpdate(lpOverlapped, lpBuffer, (a, b) => lpBuffer);
                        overlappedToDirection.AddOrUpdate(lpOverlapped, true, (a, b) => true);
                        queue.Add(String.Format("Write(Handle({0:X08}), #{1}) -> Overlapped({2:X08})", hFile.ToInt32(), nNumberOfBytesToWrite, lpOverlapped.ToInt32()));
                    }
                    // otherwise, something unexpected happened
                    else
                    {
                        queue.Add(String.Format("Write(Handle({0:X08}), #{1}) -> !!", hFile.ToInt32(), nNumberOfBytesToWrite));
                    }
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("WriteFile error: 0}", ex.Message));
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
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    queue.Add(String.Format("!! ReadEx({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("ReadFileEx Error: {0}", ex.Message));
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
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    queue.Add(String.Format("!! WriteEx({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("WriteFileEx Error: {0}", ex.Message));
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
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    queue.Add(String.Format("!! GetResult({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("GetOverlappedResult Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region GetQueuedCompletionStatus
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetQueuedCompletionStatus(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetQueuedCompletionStatus_Delegate(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds);

        private bool GetQueuedCompletionStatus_Hook(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds)
        {
            var result = GetQueuedCompletionStatus(CompletionPort, out lpNumberOfBytes, out lpCompletionKey, out lpOverlapped, dwMilliseconds);

            try
            {
                // if the completion port/key & overlapped are known
                if (ioPortToHandles.ContainsKey(CompletionPort) && completionKeyToHandle.ContainsKey(lpCompletionKey) && overlappedToBuffer.ContainsKey(lpOverlapped))
                {
                    // if the operation is complete
                    if (result)
                    {
                        // show the buffer that was read/written
                        var lpBuffer = overlappedToBuffer[lpOverlapped];
                        byte[] buffer = new byte[lpNumberOfBytes];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytes);
                        if (overlappedToDirection[lpOverlapped])
                            OnDataSent(completionKeyToHandle[lpCompletionKey], buffer);
                        else
                            OnDataReceived(completionKeyToHandle[lpCompletionKey], buffer);
                        queue.Add(String.Format("GetStatus(IO({0:X08})) = Key({2:X08}) & Overlapped({4:X08}) & [{3}]", CompletionPort.ToInt32(), lpNumberOfBytes, lpCompletionKey.ToUInt32(), BitConverter.ToString(buffer).Replace("-", ""), lpOverlapped.ToInt32()));
                    }
                    // otherwise, nothing to do
                    else
                    {
                        queue.Add(String.Format("GetStatus(IO({0:X08})) = <NOT READY>", CompletionPort.ToInt32()));
                    }
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("GetQueuedCompletionStatus Error: {0}\n{1}", ex.Message, ex.StackTrace));
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
                // not supported yet
                if (ioPortToHandles.ContainsKey(CompletionPort))
                {
                    queue.Add(String.Format("!! GetStatusEx({0:X08})", CompletionPort.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                queue.Add(String.Format("GetQueuedCompletionStatusEx Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        private void OnDataSent(IntPtr handle, byte[] data)
        {
            pcapWriters[handle].WriteEnhancedPacketBlock(true, data);
        }

        private void OnDataReceived(IntPtr handle, byte[] data)
        {
            pcapWriters[handle].WriteEnhancedPacketBlock(false, data);
        }

        private ServerInterface server = null;
        private BlockingCollection<string> queue = new BlockingCollection<string>();

        private ConcurrentDictionary<IntPtr, string> pipeHandleToName = new ConcurrentDictionary<IntPtr, string>();
        private ConcurrentDictionary<IntPtr, ConcurrentBag<IntPtr>> ioPortToHandles = new ConcurrentDictionary<IntPtr, ConcurrentBag<IntPtr>>();
        private ConcurrentDictionary<UIntPtr, IntPtr> completionKeyToHandle = new ConcurrentDictionary<UIntPtr, IntPtr>();
        private ConcurrentDictionary<IntPtr, IntPtr> overlappedToBuffer = new ConcurrentDictionary<IntPtr, IntPtr>();
        private ConcurrentDictionary<IntPtr, bool> overlappedToDirection = new ConcurrentDictionary<IntPtr, bool>(); // sending is true
        private ConcurrentDictionary<IntPtr, PCapNGWriter> pcapWriters = new ConcurrentDictionary<IntPtr, PCapNGWriter>();
    }
}