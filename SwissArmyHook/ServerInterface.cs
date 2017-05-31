using System;

namespace SwissArmyHook
{
    /// <summary>
    /// RPC class to allow hooked app to run code within SAP process
    /// </summary>
    public class ServerInterface : MarshalByRefObject
    {
        /// <summary>
        /// Report that SAP is instlled
        /// </summary>
        /// <param name="clientPID"></param>
        public void ReportInstalled(int clientPID)
        {
            Console.Error.WriteLine("SAP Hook Installed: PID = {0}", clientPID);
        }

        /// <summary>
        /// Report an informational message
        /// </summary>
        /// <param name="message"></param>
        public void ReportMessage(string message)
        {
            Console.Error.WriteLine("SAP: {0}", message);
        }

        /// <summary>
        /// Report an exception
        /// </summary>
        /// <param name="ex"></param>
        public void ReportException(Exception ex)
        {
            Console.Error.WriteLine("SAP Exception: {0}", ex.Message);
        }
    }
}
