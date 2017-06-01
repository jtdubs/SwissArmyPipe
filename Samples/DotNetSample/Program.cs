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
            Thread.Sleep(1000);

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
                        Thread.Sleep(1000);
                        writer.WriteLine("sample request");
                        Thread.Sleep(1000);
                        reader.ReadLine();
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
                        Thread.Sleep(1000);
                        reader.ReadLine();
                        Thread.Sleep(1000);
                        writer.WriteLine("sample response");
                    }
                    done.Release();
                });

                done.WaitOne();
                done.WaitOne();

                Thread.Sleep(2000);
            }
        }
    }
}
