using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using EasyHook;
using System.Threading;

namespace SwissArmyPipe
{
    class Program
   {
        static void Main(string[] args)
        {
            int pid = 0;

            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            switch (args[0].ToLower())
            {
                default:
                case "help":
                    ShowUsage();
                    break;
                case "run":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                        break;
                    }

                    RunApp(args[1], args.Skip(2).ToArray());
                    break;
                case "hook":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                        break;
                    }

                    if (int.TryParse(args[1], out pid))
                    {
                        HookPID(pid);
                    }
                    else
                    {
                        HookProcess(args[1]);
                    }

                    break;
                case "list":
                    ListPipes();
                    break;
                case "find":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                        break;
                    }

                    if (int.TryParse(args[1], out pid))
                    {
                        FindPipesByPID(pid);
                    }
                    else
                    {
                        FindPipesByProcessName(args[1]);
                    }
                    break;
                case "server":
                    if (args.Length < 2)
                    {
                        RunServer();
                    }
                    else
                    {
                        RunServer(args[1]);
                    }
                    break;
                case "client":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                        break;
                    }

                    RunClient(args[1]);
                    break;
            }
        }

        private static void ShowUsage()
        {
            Console.Error.WriteLine(
@"usage: {0}.exe [verb]

verbs:
help              - show this message
list              - list named pipes
find [pid|name]   - find pipes
client [name]     - create a named pipe client
server [name?]    - create a named pipe server
hook [pid|name]   - hook existing process
run [cmd] [args*] - hook new process",
                Assembly.GetEntryAssembly().GetName().Name.ToLower());
        }

        private static void RunServer()
        {
            RunServer(String.Format("sap-{0}", Process.GetCurrentProcess().Id));
        }

        private static void RunPipeStream(Stream stream, Func<bool> isOpen)
        {
            using (var reader = new StreamReader(stream))
            using (var writer = new StreamWriter(stream))
            {
                writer.AutoFlush = true;

                ThreadPool.QueueUserWorkItem(o => 
                {
                    try
                    {
                        while (isOpen())
                        {
                            string local = Console.ReadLine();
                            writer.WriteLine(local);
                        }
                    }
                    catch { }
                }, null);

                ThreadPool.QueueUserWorkItem(o => 
                {
                    try
                    {
                        while (isOpen())
                        {
                            string remote = reader.ReadLine();
                            Console.Out.WriteLine(remote);
                        }
                    }
                    catch { }
                }, null);

                while (isOpen())
                {
                    Thread.Sleep(1000);
                }
            }
        }

        private static void RunServer(string name)
        {
            try
            {
                var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);
                
                while (true)
                {
                    Console.Error.WriteLine("Waiting for connection to {0}...", name);
                    server.WaitForConnection();
                    Console.Error.WriteLine("Connected.");
                    RunPipeStream(server, () => server.IsConnected);
                    Console.Error.WriteLine("Client disconnected.");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: {0}", ex.Message);
            }
        }
        
        private static void RunClient(string name)
        {
            try
            {
                var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);

                Console.Error.WriteLine("Connecting to {0}...", name);
                client.Connect();
                Console.Error.WriteLine("Connected.");
                RunPipeStream(client, () => client.IsConnected);
                Console.Error.WriteLine("Server disconnected.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: {0}", ex.Message);
            }
        }

        private static void RunApp(string app, string[] args)
        {
            Console.Error.WriteLine("Creating IPC server...");
            string channelName = null;
            int pid = 0;
            var channel = RemoteHooking.IpcCreateServer<SwissArmyHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            Console.Error.WriteLine("Launching {0} with args = {1}...", app, String.Join(" ", args));
            try
            {
                var hookDLL = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "SwissArmyHook.dll");
                EasyHook.RemoteHooking.CreateAndInject(app, string.Join(" ", args), 0, EasyHook.InjectionOptions.DoNotRequireStrongName, hookDLL, hookDLL, out pid, channelName);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed: {0}", ex.Message);
                return;
            }

            Console.Error.WriteLine("Waiting for process ({0}) to exit...", pid);
            try { Process.GetProcessById(pid).WaitForExit(); } catch { }
        }

        private static void HookPID(int pid)
        {
            Console.Error.WriteLine("Creating IPC server...");
            string channelName = null;
            var channel = RemoteHooking.IpcCreateServer<SwissArmyHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            Console.Error.WriteLine("Hooking PID {0}...", pid);
            try
            {
                var hookDLL = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "SwissArmyHook.dll");
                EasyHook.RemoteHooking.Inject(pid, EasyHook.InjectionOptions.DoNotRequireStrongName, hookDLL, hookDLL, channelName);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed: {0}", ex.Message);
                return;
            }

            Console.Error.WriteLine("Waiting for process ({0}) to exit...", pid);
            try { Process.GetProcessById(pid).WaitForExit(); } catch { }
        }

        private static void HookProcess(string name)
        {
            var candidates = Process.GetProcesses().Where(p => p.ProcessName.ToLowerInvariant().Contains(name.ToLowerInvariant()));

            if (candidates.Count() == 0)
            {
                Console.Error.WriteLine("No process found matching '{0}'!", name);
                return;
            }

            if (candidates.Count() > 1)
            {
                Console.Error.WriteLine("Too many matching processes: {0}", String.Join(", ", candidates.Select(p => String.Format("{0} ({1})", p.ProcessName, p.Id)).ToArray()));
            }

            HookPID(candidates.First().Id);
        }

        private static void ListPipes()
        {
            foreach (var f in Directory.GetFiles(@"\\.\pipe\").OrderBy(l => l.ToLowerInvariant()))
            {
                var info = GetServerProcessInfo(f);
                Console.WriteLine("{0} [{1} ({2})]", Path.GetFileName(f), info.Name, info.PID);
            }
        }

        private static void ListPipesByPID()
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys)
            {     
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        private static void FindPipes(string name)
        {
            foreach (var f in Directory.GetFiles(@"\\.\pipe\").OrderBy(l => l.ToLowerInvariant()).Where(n => n.ToLowerInvariant().Contains(name.ToLowerInvariant())))
            {
                var info = GetServerProcessInfo(f);
                Console.WriteLine("{0} [{1} ({2})]", Path.GetFileName(f), info.Name, info.PID);
            }
        }

        private static void FindPipesByPID(int pid)
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys.Where(p => p.PID == pid))
            {
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        private static void FindPipesByProcessName(string name)
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys.Where(p => p.Name.Contains(name.ToLowerInvariant())))
            {
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        private static ProcessInfo GetServerProcessInfo(string f)
        {
            var fd = Native.CreateFile(f, (uint)(Native.ACCESS_MASK.GENERIC_READ | Native.ACCESS_MASK.GENERIC_WRITE), (uint)(Native.SHARE_MODE.FILE_SHARE_READ | Native.SHARE_MODE.FILE_SHARE_WRITE), IntPtr.Zero, (uint)Native.CREATION_DISPOSITION.OPEN_EXISTING, 0, IntPtr.Zero);

            if (fd.ToInt32() == -1)
                return ProcessInfo.Unknown;
           
            long pid;
            if (! Native.GetNamedPipeServerProcessId(fd, out pid))
                return ProcessInfo.Unknown;

            try
            {
                return ProcessInfo.ForPID((int)pid);
            }
            finally
            {
                Native.CloseHandle(fd);
            }
        }
    }
}
