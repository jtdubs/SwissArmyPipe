using System;

namespace SwissArmyHook
{
    /// <summary>
    /// RPC class to allow hooked app to run code within SAP process
    /// </summary>
    public class ServerInterface : MarshalByRefObject
    {
        /// <summary>
        /// Report a message
        /// </summary>
        /// <param name="message"></param>
        public void ReportMessage(string message)
        {
            Console.Error.WriteLine("SAP: {0}", message);
        }

        /// <summary>
        /// Check that RPC interface is still alive
        /// </summary>
        public void Ping()
        {
        }
    }
}
