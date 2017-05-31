using System;
using EasyHook;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

namespace SwissArmyHook
{
    /// <summary>
    /// The hook that is injectioned into the application
    /// </summary>
    public class InjectionEntryPoint : IEntryPoint
    {
        /// <summary>
        /// Construct the hook
        /// </summary>
        /// <param name="context"></param>
        /// <param name="channelName"></param>
        public InjectionEntryPoint(RemoteHooking.IContext context, string channelName)
        {
            // create RPC interface back to SAP process
            server = RemoteHooking.IpcConnectClient<ServerInterface>(channelName);
        }
        
        /// <summary>
        /// Hook the required functions
        /// </summary>
        /// <param name="context"></param>
        /// <param name="channelName"></param>
        public void Run(RemoteHooking.IContext context, string channelName)
        {
            server.ReportMessage(String.Format("Installing into {0}...", RemoteHooking.GetCurrentProcessId()));

            // hook interesting functions

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
            
            // don't run hooks on this thread, otherwise we'll recurse to our doom! 
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

            // wake up the hooked process
            RemoteHooking.WakeUpProcess();

            server.ReportMessage(String.Format("Installed into {0}.", RemoteHooking.GetCurrentProcessId()));

            try
            {
                Action action;

                // main loop
                while (true)
                {
                    // grab the next action from the queue and process it
                    if (queue.TryTake(out action, 1000))
                        action();
                    // if not action is available, just check that the RPC link is still up
                    else
                        server.Ping();
                }
            }
            catch
            {
            }

            // clean up all the hooks
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

            // final clean-up
            LocalHook.Release();
        }

        #region CreateFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateFileW(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateFile_Delegate(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);

        /// <summary>
        /// CreateFile is used to open named pipes from the client side
        /// 
        /// We need to record the Handle for foture use.
        /// </summary>
        /// <param name="lpFileName"></param>
        /// <param name="dwDesiredAccess"></param>
        /// <param name="dwShareMode"></param>
        /// <param name="lpSecurityAttributes"></param>
        /// <param name="dwCreationDisposition"></param>
        /// <param name="dwFlagsAndAttributes"></param>
        /// <param name="hTemplateFile"></param>
        /// <returns></returns>
        private IntPtr CreateFile_Hook(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile)
        {
            // call the real CreateFile function
            var handle = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
          
            try
            {
                // if a pipe was successfully opened
                if (handle.ToInt32() != -1 && lpFileName.StartsWith(@"\\.\pipe\", StringComparison.InvariantCultureIgnoreCase))
                {
                    // pcap file name
                    string pcapFilename = String.Format("client-{0}.pcapng", Path.GetFileName(lpFileName));

                    // map the handle to the original pipe name and create a pcap file
                    pipeHandleToName[handle] = lpFileName;
                    pcapWriters[handle] = new PCapNGWriter(new BinaryWriter(File.Create(pcapFilename)));

                    // report message back to SAP process
                    // OnMessage(String.Format("Handle({1:X08}) = Client(\"{0}\")", lpFileName, handle.ToInt32()));
                    OnMessage(String.Format("File '{0}' created for pipe '{1}'.", pcapFilename, lpFileName));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("CreateFile Error: {0}", ex.Message));
            }

            return handle;
        }
        #endregion

        #region CreateNamedPipe
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateNamedPipeW(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateNamedPipe_Delegate(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes);

        /// <summary>
        /// CreateNamedPipe is used to open pipes from the server side
        /// 
        /// We need to record the Handle for future use.
        /// </summary>
        /// <param name="lpName"></param>
        /// <param name="dwOpenMode"></param>
        /// <param name="dwPipeMode"></param>
        /// <param name="nMaxInstances"></param>
        /// <param name="nOutBufferSize"></param>
        /// <param name="nInBufferSize"></param>
        /// <param name="nDefaultTimeOut"></param>
        /// <param name="lpSecurityAttributes"></param>
        /// <returns></returns>
        private IntPtr CreateNamedPipe_Hook(String lpName, UInt32 dwOpenMode, UInt32 dwPipeMode, UInt32 nMaxInstances, UInt32 nOutBufferSize, UInt32 nInBufferSize, UInt32 nDefaultTimeOut, IntPtr lpSecurityAttributes)
        {
            // call real CreateNamedPipe function
            var handle = CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);

            try
            {
                // if a pipe was successfully opened
                if (handle.ToInt32() != -1)
                {
                    // pcap file name
                    string pcapFilename = String.Format("server-{0}.pcapng", Path.GetFileName(lpName));

                    // map the handle to the original pipe name and create a pcap file
                    pipeHandleToName[handle] = lpName;
                    pcapWriters[handle] = new PCapNGWriter(new BinaryWriter(File.Create(pcapFilename)));

                    // report message back to SAP process
                    // OnMessage(String.Format("Handle({1:X08}) = Server(\"{0}\")", lpName, handle.ToInt32()));
                    OnMessage(String.Format("File '{0}' created for pipe '{1}'.", pcapFilename, lpName));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("CreateNamedPipe Error: {0}", ex.Message));
            }

            return handle;
        }
        #endregion

        #region CreateIoCompletionPort
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateIoCompletionPort(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr CreateIoCompletionPort_Delegate(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads);

        /// <summary>
        /// CreateIoCompletionPort is used to map file handles to completion ports
        /// 
        /// This is commonly used in async programming and is how .NET code appears to use named pipes.
        /// We need to track the mapping from completion port/key to file handle for future use.
        /// </summary>
        /// <param name="FileHandle"></param>
        /// <param name="ExistingCompletionPort"></param>
        /// <param name="CompletionKey"></param>
        /// <param name="NumberOfConcurrentThreads"></param>
        /// <returns></returns>
        private IntPtr CreateIoCompletionPort_Hook(IntPtr FileHandle, IntPtr ExistingCompletionPort, UIntPtr CompletionKey, uint NumberOfConcurrentThreads)
        {
            // call the real CreateIoCompletionPort function
            var result = CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);

            try
            {
                // if a completion port was successfully associated with a known pipe
                if (result.ToInt32() != 0 && pipeHandleToName.ContainsKey(FileHandle))
                {
                    // associate completion port/key with pipe handle, 
                    ioPortToHandles.AddOrUpdate(result, new ConcurrentBag<IntPtr>(new IntPtr[] { FileHandle }), (n, b) => { b.Add(n); return b; });
                    completionKeyToHandle.AddOrUpdate(CompletionKey, k => FileHandle, (k, h) => FileHandle);
                    // OnMessage(String.Format("Port({0:X08}) = Handle({1:X08}) & Key({2:X08})", result.ToInt32(), FileHandle.ToInt32(), CompletionKey.ToUInt32()));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("CreateIoCompletionPort Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region ReadFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool ReadFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        /// <summary>
        /// ReadFile is used to read from a named pipe
        /// 
        /// This may be a synchronous or asynchronous operation.
        /// If it is synchronous, we can log the data here.
        /// If it is asynchronous, we will see the result when the app calls GetOverlappedResult or GetQueuedCompletionStatus.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpNumberOfBytesRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        private bool ReadFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            // call the real ReadFile function
            var result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

            try
            {
                // if the read was for a known pipe
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    // if the read succeeded
                    if (result)
                    {
                        // log the data that was read
                        byte[] buffer = new byte[lpNumberOfBytesRead];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesRead);
                        OnDataReceived(hFile, buffer);
                        // OnMessage(String.Format("Read(Handle({0:X08}), #{1}) -> [{2}]", hFile.ToInt32(), nNumberOfBytesToRead, BitConverter.ToString(buffer).Replace("-", "")));
                    }
                    // if the read is async (overlapped)
                    else if (lpOverlapped.ToInt32() != 0 && Marshal.GetLastWin32Error() == 997 /* ERROR_IO_PENDING */)
                    {
                        // associate the overlapped structure w/ the buffer
                        overlappedToBuffer.AddOrUpdate(lpOverlapped, lpBuffer, (a, b) => lpBuffer);
                        overlappedToDirection.AddOrUpdate(lpOverlapped, false, (a, b) => false);
                        // OnMessage(String.Format("Read(Handle({0:X08}), #{1}) -> Overlapped({2:X08})", hFile.ToInt32(), nNumberOfBytesToRead, lpOverlapped.ToInt32()));
                    }
                    // otherwise, something unexpected happened
                    else
                    {
                        OnMessage(String.Format("Read(Handle({0:X08}), @{1}) = !!", hFile.ToInt32(), nNumberOfBytesToRead));
                    }
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("ReadFile Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region WriteFile
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool WriteFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped);

        /// <summary>
        /// WriteFile is used to write to a named pipe
        /// 
        /// This may be a synchronous or asynchronous operation.
        /// If it is synchronous, we can log the data here.
        /// If it is asynchronous, we will see the result when the app calls GetOverlappedResult or GetQueuedCompletionStatus.
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpNumberOfBytesWritten"></param>
        /// <param name="lpOverlapped"></param>
        /// <returns></returns>
        private bool WriteFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpNumberOfBytesWritten, IntPtr lpOverlapped)
        {
            // call the real WriteFile function
            var result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

            try
            {
                // if the write was for a pipe
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    // if the write succeeded
                    if (result)
                    {
                        // log the data that was written
                        int count = lpNumberOfBytesWritten == IntPtr.Zero ? (int)nNumberOfBytesToWrite : Marshal.ReadInt32(lpNumberOfBytesWritten); // uint -> int !!
                        byte[] buffer = new byte[count];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)count);
                        OnDataSent(hFile, buffer);
                        // OnMessage(String.Format("Write(Handle({0:X08}), #{1}) -> [{2}]", hFile.ToInt32(), nNumberOfBytesToWrite, BitConverter.ToString(buffer).Replace("-", "")));
                    }
                    // if the read is async (overlapped)
                    else if (lpOverlapped.ToInt32() != 0 && Marshal.GetLastWin32Error() == 997 /* ERROR_IO_PENDING */)
                    {
                        // associate the overlapped structure w/ the buffer
                        overlappedToBuffer.AddOrUpdate(lpOverlapped, lpBuffer, (a, b) => lpBuffer);
                        overlappedToDirection.AddOrUpdate(lpOverlapped, true, (a, b) => true);
                        // OnMessage(String.Format("Write(Handle({0:X08}), #{1}) -> Overlapped({2:X08})", hFile.ToInt32(), nNumberOfBytesToWrite, lpOverlapped.ToInt32()));
                    }
                    // otherwise, something unexpected happened
                    else
                    {
                        OnMessage(String.Format("Write(Handle({0:X08}), #{1}) -> !!", hFile.ToInt32(), nNumberOfBytesToWrite));
                    }
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("WriteFile error: 0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region ReadFileEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadFileEx(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool ReadFileEx_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        /// <summary>
        /// ReadFileEx is used to read from a named pipe asynchronously
        /// 
        /// We don't currently support this path.  :(
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToRead"></param>
        /// <param name="lpOverlapped"></param>
        /// <param name="lpCompletionRoutine"></param>
        /// <returns></returns>
        private bool ReadFileEx_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine)
        {
            
            var result = ReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);

            try
            {
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    OnMessage(String.Format("!! ReadEx({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("ReadFileEx Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region WriteFileEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool WriteFileEx(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool WriteFileEx_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine);

        /// <summary>
        /// WriteFileEx is used to write to a named pipe asynchronously
        /// 
        /// We don't currently support this path.  :(
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpBuffer"></param>
        /// <param name="nNumberOfBytesToWrite"></param>
        /// <param name="lpOverlapped"></param>
        /// <param name="lpCompletionRoutine"></param>
        /// <returns></returns>
        private bool WriteFileEx_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, IntPtr lpOverlapped, IOCompletionCallback lpCompletionRoutine)
        {
            var result = WriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);

            try
            {
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    OnMessage(String.Format("!! WriteEx({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("WriteFileEx Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region GetOverlappedResult
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetOverlappedResult(IntPtr hFile, IntPtr lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetOverlappedResult_Delegate(IntPtr hFile, IntPtr lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

        /// <summary>
        /// GetOverlappedResult is used to get the result of an OVERLAPPED async operation
        /// 
        /// This is not currently supported as .NET code uses IO completion ports instead.
        /// TODO: add support for this
        /// </summary>
        /// <param name="hFile"></param>
        /// <param name="lpOverlapped"></param>
        /// <param name="lpNumberOfBytesTransferred"></param>
        /// <param name="bWait"></param>
        /// <returns></returns>
        private bool GetOverlappedResult_Hook(IntPtr hFile, IntPtr lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait)
        {
            var result = GetOverlappedResult(hFile, lpOverlapped, out lpNumberOfBytesTransferred, bWait);

            try
            {
                // not supported yet
                if (pipeHandleToName.ContainsKey(hFile))
                {
                    OnMessage(String.Format("!! GetResult({0:X08})", hFile.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("GetOverlappedResult Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        #region GetQueuedCompletionStatus
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetQueuedCompletionStatus(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetQueuedCompletionStatus_Delegate(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds);

        /// <summary>
        /// GetQueuedCompletionStatus is used to check if an async IO operation is complete
        /// 
        /// If it is, we log the sent/received data here.
        /// </summary>
        /// <param name="CompletionPort"></param>
        /// <param name="lpNumberOfBytes"></param>
        /// <param name="lpCompletionKey"></param>
        /// <param name="lpOverlapped"></param>
        /// <param name="dwMilliseconds"></param>
        /// <returns></returns>
        private bool GetQueuedCompletionStatus_Hook(IntPtr CompletionPort, out uint lpNumberOfBytes, out UIntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds)
        {
            // call the real GetQueuedCompletionStatus function
            var result = GetQueuedCompletionStatus(CompletionPort, out lpNumberOfBytes, out lpCompletionKey, out lpOverlapped, dwMilliseconds);

            try
            {
                // if the completion port/key & overlapped are known
                if (ioPortToHandles.ContainsKey(CompletionPort) && completionKeyToHandle.ContainsKey(lpCompletionKey) && overlappedToBuffer.ContainsKey(lpOverlapped))
                {
                    // if the operation is complete
                    if (result)
                    {
                        // get the buffer that was sent/recieved
                        var lpBuffer = overlappedToBuffer[lpOverlapped];
                        byte[] buffer = new byte[lpNumberOfBytes];
                        Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytes);

                        // log the buffer
                        if (overlappedToDirection[lpOverlapped])
                            OnDataSent(completionKeyToHandle[lpCompletionKey], buffer);
                        else
                            OnDataReceived(completionKeyToHandle[lpCompletionKey], buffer);

                        // OnMessage(String.Format("GetStatus(IO({0:X08})) = Key({2:X08}) & Overlapped({4:X08}) & [{3}]", CompletionPort.ToInt32(), lpNumberOfBytes, lpCompletionKey.ToUInt32(), BitConverter.ToString(buffer).Replace("-", ""), lpOverlapped.ToInt32()));
                    }
                    // otherwise, nothing to do
                    else
                    {
                        OnMessage(String.Format("GetStatus(IO({0:X08})) = <NOT READY>", CompletionPort.ToInt32()));
                    }
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("GetQueuedCompletionStatus Error: {0}\n{1}", ex.Message, ex.StackTrace));
            }

            return result;
        }
        #endregion

        #region GetQueuedCompletionStatusEx
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool GetQueuedCompletionStatusEx(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool GetQueuedCompletionStatusEx_Delegate(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable);

        /// <summary>
        /// GetQueuedCompletionStatusEx is used to check that status of multiple IO completion ports at the same time
        /// 
        /// This is not currently supported.
        /// </summary>
        /// <param name="CompletionPort"></param>
        /// <param name="lpCompletionPortEntries"></param>
        /// <param name="ulCount"></param>
        /// <param name="ulNumEntriesRemoved"></param>
        /// <param name="dwMilliseconds"></param>
        /// <param name="fAlertable"></param>
        /// <returns></returns>
        private bool GetQueuedCompletionStatusEx_Hook(IntPtr CompletionPort, IntPtr lpCompletionPortEntries, uint ulCount, out uint ulNumEntriesRemoved, uint dwMilliseconds, bool fAlertable)
        {
            var result = GetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries, ulCount, out ulNumEntriesRemoved, dwMilliseconds, fAlertable);

            try
            {
                // not supported yet
                if (ioPortToHandles.ContainsKey(CompletionPort))
                {
                    OnMessage(String.Format("!! GetStatusEx({0:X08})", CompletionPort.ToInt32()));
                }
            }
            catch (Exception ex)
            {
                OnMessage(String.Format("GetQueuedCompletionStatusEx Error: {0}", ex.Message));
            }

            return result;
        }
        #endregion

        /// <summary>
        /// Log transmitted pipe data
        /// </summary>
        /// <param name="handle"></param>
        /// <param name="data"></param>
        private void OnDataSent(IntPtr handle, byte[] data)
        {
            // pretend IPC data was in a UDP/IP packet on loopback from port 1000 -> 2000
            queue.Add(() => pcapWriters[handle].WriteIPPacketBlock(0x7F000001, 1000, 0x7F000001, 2000, data));
        }

        /// <summary>
        /// Log received pipe data
        /// </summary>
        /// <param name="handle"></param>
        /// <param name="data"></param>
        private void OnDataReceived(IntPtr handle, byte[] data)
        {
            // pretend IPC data was in a UDP/IP packet on loopback from port 2000 -> 1000
            queue.Add(() => pcapWriters[handle].WriteIPPacketBlock(0x7F000001, 2000, 0x7F000001, 1000, data));
        }

        /// <summary>
        /// Transmit a message to the SAP process
        /// </summary>
        /// <param name="message"></param>
        private void OnMessage(string message)
        {
            queue.Add(() => server.ReportMessage(message));
        }

        private ServerInterface server = null;
        private BlockingCollection<Action> queue = new BlockingCollection<Action>();

        private ConcurrentDictionary<IntPtr, string> pipeHandleToName = new ConcurrentDictionary<IntPtr, string>();
        private ConcurrentDictionary<IntPtr, ConcurrentBag<IntPtr>> ioPortToHandles = new ConcurrentDictionary<IntPtr, ConcurrentBag<IntPtr>>();
        private ConcurrentDictionary<UIntPtr, IntPtr> completionKeyToHandle = new ConcurrentDictionary<UIntPtr, IntPtr>();
        private ConcurrentDictionary<IntPtr, IntPtr> overlappedToBuffer = new ConcurrentDictionary<IntPtr, IntPtr>();
        private ConcurrentDictionary<IntPtr, bool> overlappedToDirection = new ConcurrentDictionary<IntPtr, bool>(); // sending is true
        private ConcurrentDictionary<IntPtr, PCapNGWriter> pcapWriters = new ConcurrentDictionary<IntPtr, PCapNGWriter>();
    }
}