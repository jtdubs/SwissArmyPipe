using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyHook;
using System.Runtime.InteropServices;
using System.Threading;

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

            var createFileHook = EasyHook.LocalHook.Create(
               EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
               new CreateFile_Delegate(CreateFile_Hook),
               this);

            var readFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "ReadFile"),
                new ReadFile_Delegate(ReadFile_Hook),
                this);

            var writeFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "WriteFile"),
                new WriteFile_Delegate(WriteFile_Hook),
                this);

            createFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            readFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            writeFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            
            server.ReportMessage("Installed!");
            RemoteHooking.WakeUpProcess();

            try
            {
                while (true)
                {
                    System.Threading.Thread.Sleep(500);
                    string[] queued = null;
                    lock (queue)
                    {
                        queued = queue.ToArray();
                        queue.Clear();
                    }
                    if (queued != null) server.ReportMessages(queued);
                    else server.Ping();
                }
            }
            catch
            {
            }

            createFileHook.Dispose();
            readFileHook.Dispose();
            writeFileHook.Dispose();

            LocalHook.Release();
        }

        // GetOverlappedResult https://msdn.microsoft.com/en-us/library/windows/desktop/ms683209(v=vs.85).aspx
        // CreateIoCompletionPort  https://msdn.microsoft.com/en-us/library/windows/desktop/aa363862(v=vs.85).aspx
        // GetQueuedCompletionStatus  https://msdn.microsoft.com/en-us/library/windows/desktop/aa364986(v=vs.85).aspx

        #region CreateFile
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateFile_Delegate(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateFileW(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

        private IntPtr CreateFile_Hook(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile)
        {
            var handle = CreateFileW(filename, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
          
            try
            {
                if (handle.ToInt32() == -1)
                    return handle;

                if (String.IsNullOrEmpty(filename))
                    return handle;
                
                if (!filename.StartsWith(@"\\.\pipe\", StringComparison.InvariantCultureIgnoreCase))
                    return handle;
                   
                namedPipeHandles[handle] = filename;

                lock (queue)
                {
                    queue.Enqueue(String.Format("CreateFile(\"{0}\") = {1:X08}", filename, handle.ToInt32()));
                }
            }
            catch
            {
            }

            return handle;
        }
        #endregion

        #region ReadFile
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool ReadFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool ReadFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        private bool ReadFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped)
        {
            if (!namedPipeHandles.ContainsKey(hFile))
                return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

            bool result = false;

            if (lpOverlapped == IntPtr.Zero)
            {
                result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

                if (result)
                {
                    byte[] buffer = new byte[lpNumberOfBytesRead];
                    Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesRead);

                    lock (queue)
                    {
                        queue.Enqueue(String.Format("ReadFile({0:X08}) = {1}", hFile.ToInt32(), BitConverter.ToString(buffer)));
                    }
                }
            }
            else
            {
                result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

                if (result)
                {
                    lock (queue)
                    {
                        queue.Enqueue(String.Format("ReadFile({0:X08}) = async success", hFile.ToInt32()));
                    }
                }
                else if (Marshal.GetLastWin32Error() == 997) // ERROR_IO_PENDING
                {
                    var overlapped = Marshal.PtrToStructure<NativeOverlapped>(lpOverlapped);

                    lock (queue)
                    {
                        queue.Enqueue(String.Format("ReadFile({0:X08}) = async: {1:X08}", hFile.ToInt32(), lpOverlapped.ToInt32()));
                    }
                }
                else
                {
                    var overlapped = Marshal.PtrToStructure<NativeOverlapped>(lpOverlapped);

                    lock (queue)
                    {
                        queue.Enqueue(String.Format("ReadFile({0:X08}) = async fail: {1}, {2}", hFile.ToInt32(), Marshal.GetLastWin32Error(), overlapped.InternalLow));
                    }
                }
            }
            
            return result;
        }
        #endregion

        #region WriteFile
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        delegate bool WriteFile_Delegate(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteFile(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        private bool WriteFile_Hook(IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped)
        {
            if (!namedPipeHandles.ContainsKey(hFile))
                return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);

            bool result = false;

            if (lpOverlapped == IntPtr.Zero)
            {
                result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);

                if (result)
                {
                    // byte[] buffer = new byte[lpNumberOfBytesWritten];
                    // Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesWritten);

                    lock (queue)
                    {
                        queue.Enqueue(String.Format("WriteFile({0:X08}) = {1}", hFile.ToInt32(), "data")); // BitConverter.ToString(buffer)));
                    }
                }
            }
            else
            {
                result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);

                // var overlapped = Marshal.PtrToStructure<NativeOverlapped>(lpOverlapped);

                /*new ManualResetEvent()

                var newOverlapped = new NativeOverlapped()
                {
                    OffsetLow = overlapped.OffsetLow,
                    OffsetHigh = overlapped.OffsetHigh,
                    EventHandle = CreateEvent(IntPtr.Zero, true, false, null)
                };*/

                lock (queue)
                {
                    queue.Enqueue(String.Format("WriteFile({0:X08}) = {1}", hFile.ToInt32(), "overlapped")); // overlapped.ToString()));
                }
            }


            return result;
        }
        #endregion

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        private ServerInterface server = null;
        private Queue<string> queue = new Queue<string>();
        private Dictionary<IntPtr, string> namedPipeHandles = new Dictionary<IntPtr, string>();
    }
}