using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using EasyHook;
using System.Threading;

namespace SwissArmyPipe
{
    /// <summary>
    /// Main class for SwissArmyPipe command-line tool
    /// </summary>
    class Program
    {
        /// <summary>
        /// Entry point for command-line tool.
        /// 
        /// Parse command-line arguments and dispach to correct helper function.
        /// </summary>
        /// <param name="args">command-line arguments</param>
        static void Main(string[] args)
        {
            int pid = 0;

            // if not args supplied, just show usage info
            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            // dispatch based on specified verb
            switch (args[0].ToLower())
            {
                // "help" (the default) just shows usage info
                default:
                case "help":
                    ShowUsage();
                    break;

                // "run" launches an application and monitors its pipe usage
                case "run":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                    }
                    else
                    {
                        RunApp(args[1], args.Skip(2).ToArray());
                    }
                    break;

                // "hook" attaches to a running application and monitors its pipe usage
                case "hook":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                    }
                    else if (int.TryParse(args[1], out pid))
                    {
                        HookPID(pid);
                    }
                    else
                    {
                        HookProcess(args[1]);
                    }
                    break;

                // "list" enumerates the pipes on the system
                case "list":
                    ListPipes();
                    break;

                // "find" locates pipes by pid or process name
                case "find":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                    }
                    else if (int.TryParse(args[1], out pid))
                    {
                        FindPipesByPID(pid);
                    }
                    else
                    {
                        FindPipesByProcessName(args[1]);
                    }
                    break;

                // "server" creates a trivial, text-based named pipe server
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

                // "client" creates a trivial, text-based named pipe client
                case "client":
                    if (args.Length < 2)
                    {
                        ShowUsage();
                    }
                    else
                    {
                        RunClient(args[1]);
                    }
                    break;
            }
        }

        /// <summary>
        /// Show usage information
        /// </summary>
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

        /// <summary>
        /// Run a simple named pipe server with a generated name
        /// </summary>
        private static void RunServer()
        {
            RunServer(String.Format("sap-{0}", Process.GetCurrentProcess().Id));
        }

        /// <summary>
        /// Run a simple named pipe server with the specified name
        /// </summary>
        /// <param name="name">Pipe name</param>
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

        /// <summary>
        /// Run a simple named pipe client attached to the given pipe
        /// </summary>
        /// <param name="name">Pipe name</param>
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

        /// <summary>
        /// Helper function for managing an interacive named pipe stream
        /// </summary>
        /// <param name="stream">Named pipe stream</param>
        /// <param name="isOpen">Helper function to determine if pipe is open</param>
        private static void RunPipeStream(Stream stream, Func<bool> isOpen)
        {
            using (var reader = new StreamReader(stream))
            using (var writer = new StreamWriter(stream))
            {
                writer.AutoFlush = true;

                // background thread for Console -> Pipe
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

                // background thread for Pipe -> Console
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

                // loop while pipe is still open
                while (isOpen())
                {
                    Thread.Sleep(1000);
                }
            }
        }

        /// <summary>
        /// Launch a "hooked" application
        /// </summary>
        /// <param name="app">full path to app</param>
        /// <param name="args">command-line arguments</param>
        private static void RunApp(string app, string[] args)
        {
            // setup hooking
            string channelName = null;
            int pid = 0;
            var channel = RemoteHooking.IpcCreateServer<SwissArmyHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            Console.Error.WriteLine("SAP: Launching {0} with args = {1}...", app, String.Join(" ", args));
            try
            {
                // create the hooked process
                var hookDLL = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "SwissArmyHook.dll");
                RemoteHooking.CreateAndInject(app, string.Join(" ", args), 0, InjectionOptions.DoNotRequireStrongName, hookDLL, hookDLL, out pid, channelName, Directory.GetCurrentDirectory());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed: {0}", ex.Message);
                return;
            }

            // wait for process to exit
            try { Process.GetProcessById(pid).WaitForExit(); } catch { }
        }

        /// <summary>
        /// Hook an existing application
        /// </summary>
        /// <param name="pid"></param>
        private static void HookPID(int pid)
        {
            // setup hooking
            Console.Error.WriteLine("Creating IPC server...");
            string channelName = null;
            var channel = RemoteHooking.IpcCreateServer<SwissArmyHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            Console.Error.WriteLine("Hooking PID {0}...", pid);
            try
            {
                // hook existing process
                var hookDLL = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "SwissArmyHook.dll");
                RemoteHooking.Inject(pid, InjectionOptions.DoNotRequireStrongName, hookDLL, hookDLL, channelName, Directory.GetCurrentDirectory());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed: {0}", ex.Message);
                return;
            }

            // wait for process to exit
            Console.Error.WriteLine("Waiting for process ({0}) to exit...", pid);
            try { Process.GetProcessById(pid).WaitForExit(); } catch { }
        }

        /// <summary>
        /// Hook an existing process
        /// </summary>
        /// <param name="name">Name of process</param>
        private static void HookProcess(string name)
        {
            // find running process that match specified name
            var candidates = Process.GetProcesses().Where(p => p.ProcessName.ToLowerInvariant().Contains(name.ToLowerInvariant()));

            // if there are no matches, fail
            if (candidates.Count() == 0)
            {
                Console.Error.WriteLine("No process found matching '{0}'!", name);
                return;
            }

            // if there are multiple matches, fail
            if (candidates.Count() > 1)
            {
                Console.Error.WriteLine("Too many matching processes: {0}", String.Join(", ", candidates.Select(p => String.Format("{0} ({1})", p.ProcessName, p.Id)).ToArray()));
            }

            // hook the only match
            HookPID(candidates.First().Id);
        }

        /// <summary>
        /// List all named pipes, and the process that has them open
        /// </summary>
        private static void ListPipes()
        {
            foreach (var f in Directory.GetFiles(@"\\.\pipe\").OrderBy(l => l.ToLowerInvariant()))
            {
                var info = GetServerProcessInfo(f);
                Console.WriteLine("{0} [{1} ({2})]", Path.GetFileName(f), info.Name, info.PID);
            }
        }

        /// <summary>
        /// List all named pipes, grouped by the process that has them open
        /// </summary>
        private static void ListPipesByPID()
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys)
            {     
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        /// <summary>
        /// List all named pipes in use by the specified process
        /// </summary>
        /// <param name="pid">PID of process</param>
        private static void FindPipesByPID(int pid)
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys.Where(p => p.PID == pid))
            {
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        /// <summary>
        /// List all named pipes in use by the specified process
        /// </summary>
        /// <param name="name">name of process</param>
        private static void FindPipesByProcessName(string name)
        {
            var map = Directory.GetFiles(@"\\.\pipe\").GroupBy(f => GetServerProcessInfo(f)).ToDictionary(g => g.Key, g => g.ToList());

            foreach (var process in map.Keys.Where(p => p.Name.Contains(name.ToLowerInvariant())))
            {
                Console.WriteLine("{0} ({1}) - {2}", process.Name, process.PID, String.Join(", ", map[process].Select(p => Path.GetFileName(p))));
            }
        }

        /// <summary>
        /// Helper function to get process metadat afor given pipe
        /// </summary>
        /// <param name="f"></param>
        /// <returns></returns>
        private static ProcessInfo GetServerProcessInfo(string f)
        {
            // try to connect to the pipe
            var fd = Native.CreateFile(f, (uint)(Native.ACCESS_MASK.GENERIC_READ | Native.ACCESS_MASK.GENERIC_WRITE), (uint)(Native.SHARE_MODE.FILE_SHARE_READ | Native.SHARE_MODE.FILE_SHARE_WRITE), IntPtr.Zero, (uint)Native.CREATION_DISPOSITION.OPEN_EXISTING, 0, IntPtr.Zero);

            // if cannot open, fail
            if (fd.ToInt32() == -1)
                return ProcessInfo.Unknown;

            try
            {
                // if unable to get PID, fail
                long pid;
                if (! Native.GetNamedPipeServerProcessId(fd, out pid))
                    return ProcessInfo.Unknown;

            
                // return process metadata for PID
                return ProcessInfo.ForPID((int)pid);
            }
            finally
            {
                // ensure handle gets closed
                Native.CloseHandle(fd);
            }
        }
    }
}
