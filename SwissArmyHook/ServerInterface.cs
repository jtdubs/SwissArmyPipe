using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyHook;

namespace SwissArmyHook
{
    public class ServerInterface : MarshalByRefObject
    {
        public void IsInstalled(int clientPID)
        {
            Console.WriteLine("Installed into PID {0}", clientPID);
        }

        public void ReportMessages(string[] messages)
        {
            foreach (var m in messages)
                Console.WriteLine("Message: {0}", m);
        }

        public void ReportMessage(string message)
        {
            Console.WriteLine("Message: {0}", message);
        }

        public void ReportException(Exception ex)
        {
            Console.WriteLine("Exception: {0}", ex.Message);
        }

        int count = 0;
        public void Ping()
        {
            var oldTop = Console.CursorTop;
            var oldLeft = Console.CursorLeft;
            Console.CursorVisible = false;

            var chars = "\\|/-";
            Console.SetCursorPosition(Console.WindowWidth - 1, oldTop - 1);
            Console.Write(chars[count++ % chars.Length]);

            Console.SetCursorPosition(oldLeft, oldTop);
            Console.CursorVisible = true;
        }
    }
}
