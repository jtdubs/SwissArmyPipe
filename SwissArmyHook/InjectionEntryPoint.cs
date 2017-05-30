using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyHook;
using System.Runtime.InteropServices;

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

        #region CreateFile
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateFile_Delegate(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateFileW(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

        private IntPtr CreateFile_Hook(String filename, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes, UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile)
        {
            if (String.IsNullOrEmpty(filename) || ! filename.StartsWith(@"\\.\pipe\", StringComparison.InvariantCultureIgnoreCase))
                return CreateFileW(filename, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);

            var handle = CreateFileW(filename, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);

            try
            {
                namedPipeHandles[handle] = filename;

                lock (queue)
                {
                    queue.Enqueue(
                        string.Format("[{0}:{1}]: PIPE \"{2}\" OPENED ({3:X08})",
                                EasyHook.RemoteHooking.GetCurrentProcessId(),
                                EasyHook.RemoteHooking.GetCurrentThreadId(),
                                filename,
                                handle.ToInt32()));
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
            bool result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);

            try
            {
                if (!result || !namedPipeHandles.ContainsKey(hFile))
                    return result;

                /*
                // byte[] buffer = new byte[lpNumberOfBytesRead];
                // Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesRead);
                */

                lock (queue)
                {
                    queue.Enqueue(string.Format("ReadFile({0:X08}, {1:X08}, {2}, {3}, {4:X08})", 0, 0, 0, 0, 0));
                }
            }
            catch
            {
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
            bool result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, out lpNumberOfBytesWritten, lpOverlapped);
               
            try
            {
                if (!namedPipeHandles.ContainsKey(hFile))
                    return result;

                /*
                byte[] buffer = new byte[lpNumberOfBytesWritten];
                Marshal.Copy(lpBuffer, buffer, 0, (int)lpNumberOfBytesWritten);
                lock (queue)
                {
                    queue.Enqueue(
                        string.Format("[{0}:{1}]: {3:X016} < {4}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(),
                                EasyHook.RemoteHooking.GetCurrentThreadId(),
                                hFile.ToInt64(),
                                BitConverter.ToString(buffer)));
                }
                */
            }
            catch
            {
            }

            return result;
        }
        #endregion

        private ServerInterface server = null;
        private Queue<string> queue = new Queue<string>();
        private Dictionary<IntPtr, string> namedPipeHandles = new Dictionary<IntPtr, string>();
    }
}