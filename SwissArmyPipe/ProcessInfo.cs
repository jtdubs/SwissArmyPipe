using System.Diagnostics;

namespace SwissArmyPipe
{
    /// <summary>
    /// Stores metadata about a running process
    /// </summary>
    public class ProcessInfo
    {
        /// <summary>
        /// Default data for "unknown" processes, such as ones that we can't access or have exited
        /// </summary>
        public static ProcessInfo Unknown = new ProcessInfo() { PID = -1, Name = "unknown" };

        /// <summary>
        /// Get process metadata for a given process
        /// </summary>
        /// <param name="pid">PID of the process</param>
        /// <returns>Process metadata</returns>
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

        public ProcessInfo() { }

        /// <summary>
        /// PID of the process
        /// </summary>
        public int PID { get; set; }

        /// <summary>
        /// Name of the process
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Ensure ProcessInfo instances for the same process hash to the same value
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return PID;
        }

        /// <summary>
        /// Equality is based on the hash codes
        /// </summary>
        /// <param name="obj">Other object</param>
        /// <returns>True if equals, false otherwise</returns>
        public override bool Equals(object obj)
        {
            return obj.GetHashCode() == this.GetHashCode();
        }
    }
}
