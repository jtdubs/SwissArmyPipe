using System.Diagnostics;

namespace SwissArmyPipe
{
    public class ProcessInfo
    {
        public static ProcessInfo Unknown = new ProcessInfo() { PID = -1, Name = "unknown" };

        public static ProcessInfo ForPID(int pid)
        {
            try
            {
                return new ProcessInfo() { PID = pid, Name = Process.GetProcessById(pid).ProcessName.ToLowerInvariant() };
            }
            catch
            {
                return new ProcessInfo() { PID = pid };
            }
        }

        public ProcessInfo() { PID = 0;  Name = "unknown"; }

        public int PID { get; set; }
        public string Name { get; set; }

        public override int GetHashCode()
        {
            return PID;
        }

        public override bool Equals(object obj)
        {
            return obj.GetHashCode() == this.GetHashCode();
        }
    }
}
