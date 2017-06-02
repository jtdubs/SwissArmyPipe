using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DotNetSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Thread.Sleep(2000);
            TestAsyncMessages();
            Thread.Sleep(2000);
            TestSyncMessages();
            Thread.Sleep(2000);
            TestAsyncBytes();
            Thread.Sleep(2000);
            TestSyncBytes();
            Thread.Sleep(2000);
        }

        private static void TestAsyncMessages()
        {
            Console.WriteLine("Testing .NET Async Messages...");

            using (var done = new Semaphore(0, 2))
            using (var server = new NamedPipeServerStream("dotnet_async_message", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous))
            using (var client = new NamedPipeClientStream(".", "dotnet_async_message", PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    server.WaitForConnection();
                    var writer = new StreamWriter(server);
                    var reader = new StreamReader(server);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        writer.WriteLine("sample request");
                        if (!reader.ReadLine().Equals("sample response"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                    }
                    done.Release();
                });

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    client.Connect();
                    var writer = new StreamWriter(client);
                    var reader = new StreamReader(client);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        if (!reader.ReadLine().Equals("sample request"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                        writer.WriteLine("sample response");
                    }
                    done.Release();
                });

                done.WaitOne();
                done.WaitOne();
            }

            Console.WriteLine("Done.");
        }

        private static void TestSyncMessages()
        {
            Console.WriteLine("Testing .NET Messages...");

            using (var done = new Semaphore(0, 2))
            using (var server = new NamedPipeServerStream("dotnet_sync_message", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.None))
            using (var client = new NamedPipeClientStream(".", "dotnet_sync_message", PipeDirection.InOut, PipeOptions.None))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    server.WaitForConnection();
                    var writer = new StreamWriter(server);
                    var reader = new StreamReader(server);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        writer.WriteLine("sample request");
                        if (!reader.ReadLine().Equals("sample response"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                    }
                    done.Release();
                });

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    client.Connect();
                    var writer = new StreamWriter(client);
                    var reader = new StreamReader(client);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        if (!reader.ReadLine().Equals("sample request"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                        writer.WriteLine("sample response");
                    }
                    done.Release();
                });

                done.WaitOne();
                done.WaitOne();
            }

            Console.WriteLine("Done.");
        }

        private static void TestAsyncBytes()
        {
            Console.WriteLine("Testing .NET Async Bytes...");

            using (var done = new Semaphore(0, 2))
            using (var server = new NamedPipeServerStream("dotnet_async_byte", PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
            using (var client = new NamedPipeClientStream(".", "dotnet_async_byte", PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    server.WaitForConnection();
                    var writer = new StreamWriter(server);
                    var reader = new StreamReader(server);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        writer.WriteLine("sample request");
                        if (!reader.ReadLine().Equals("sample response"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                    }
                    done.Release();
                });

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    client.Connect();
                    var writer = new StreamWriter(client);
                    var reader = new StreamReader(client);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        if (!reader.ReadLine().Equals("sample request"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                        writer.WriteLine("sample response");
                    }
                    done.Release();
                });

                done.WaitOne();
                done.WaitOne();
            }

            Console.WriteLine("Done.");
        }

        private static void TestSyncBytes()
        {
            Console.WriteLine("Testing .NET Bytes...");

            using (var done = new Semaphore(0, 2))
            using (var server = new NamedPipeServerStream("dotnet_sync_byte", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.None))
            using (var client = new NamedPipeClientStream(".", "dotnet_sync_byte", PipeDirection.InOut, PipeOptions.None))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    server.WaitForConnection();
                    var writer = new StreamWriter(server);
                    var reader = new StreamReader(server);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        writer.WriteLine("sample request");
                        if (!reader.ReadLine().Equals("sample response"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                    }
                    done.Release();
                });

                ThreadPool.QueueUserWorkItem(_ =>
                {
                    client.Connect();
                    var writer = new StreamWriter(client);
                    var reader = new StreamReader(client);
                    writer.AutoFlush = true;
                    for (int i = 0; i < 10; i++)
                    {
                        if (!reader.ReadLine().Equals("sample request"))
                        {
                            Console.WriteLine("Invalid response received!");
                            Thread.Sleep(1000);
                            Environment.Exit(1);
                        }
                        writer.WriteLine("sample response");
                    }
                    done.Release();
                });

                done.WaitOne();
                done.WaitOne();
            }

            Console.WriteLine("Done.");
        }
    }
}
