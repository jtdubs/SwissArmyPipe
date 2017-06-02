using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace SwissArmyHook
{
    /// <summary>
    /// Simple writer for .pcapng file format
    /// </summary>
    public class PCapNGWriter
    {
        /// <summary>
        /// Create a writer on top of the given BinaryWriter
        /// </summary>
        /// <param name="writer"></param>
        public PCapNGWriter(BinaryWriter writer)
        {
            this.writer = writer;

            // automatically write out mandatory headers
            WriteSectionHeaderBlock();
            WriteInterfaceDescriptorBlock();

            // alert that header is written
            headerWritten.Set();
        }

        /// <summary>
        /// Write mandatory Section Header Block
        /// </summary>
        private void WriteSectionHeaderBlock()
        {
            writer.Write((UInt32)0x0A0D0D0A);          // block type
            writer.Write((UInt32)28);                  // block length
            writer.Write((UInt32)0x1A2B3C4D);          // magic
            writer.Write((UInt16)1);                   // major
            writer.Write((UInt16)0);                   // minor
            writer.Write((UInt64)0xFFFFFFFFFFFFFFFFL); // section length
            writer.Write((UInt32)28);                  // block length
            writer.Flush();
        }

        /// <summary>
        /// Write mandatory Interface Descriptor Block
        /// </summary>
        private void WriteInterfaceDescriptorBlock()
        {
            writer.Write((UInt32)0x00000001);    // block type
            writer.Write((UInt32)52);            // block length
            writer.Write((UInt16)101);           // LINKTYPE_RAW
            writer.Write((UInt16)0);             // reserved
            writer.Write((UInt32)0);             // snap len
                                                    // options {
            writer.Write((UInt16)2);             // if_name
            writer.Write((UInt16)3);             // len
            writer.Write("SAP\0".ToCharArray());
            writer.Write((UInt16)3);             // if_description
            writer.Write((UInt16)13);            // len
            writer.Write("SwissArmyPipe\0\0\0".ToCharArray());
            writer.Write((UInt16)0);             // opt_endofopt
            writer.Write((UInt16)0);             // len
                                                    // }
            writer.Write((UInt32)52);            // block length
            writer.Flush();
        }

        /// <summary>
        /// Write simulated "UDP/IP" packet
        /// </summary>
        /// <param name="srcIP"></param>
        /// <param name="srcPort"></param>
        /// <param name="dstIP"></param>
        /// <param name="dstPort"></param>
        /// <param name="packet"></param>
        public void WriteIPPacketBlock(UInt32 srcIP, UInt16 srcPort, UInt32 dstIP, UInt16 dstPort, byte[] packet)
        {
            DateTime time = DateTime.Now;

            // split big packets based on UDP MTU
            for (int i = 0; i < packet.Length; i += 65507)
            {
                WriteIPPacketBlock(srcIP, srcPort, dstIP, dstPort, packet, time, i, Math.Min(65507, packet.Length - i));
            }
        }

        /// <summary>
        /// Write simulated "UDP/IP" packet
        /// </summary>
        /// <param name="srcIP"></param>
        /// <param name="srcPort"></param>
        /// <param name="dstIP"></param>
        /// <param name="dstPort"></param>
        /// <param name="packet"></param>
        public void WriteIPPacketBlock(UInt32 srcIP, UInt16 srcPort, UInt32 dstIP, UInt16 dstPort, byte[] packet, DateTime packetTime, int offset, int length)
        {
            // ensure header is written first, for multi-threaded use
            headerWritten.WaitOne();

            // calculate packet time and required lengths
            ulong time = (ulong)((packetTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds * 1000);
            int padding = (4 - (length % 4)) % 4;

            uint udpLen = (uint)(8 + length);
            uint tcpLen = (uint)(20 + udpLen);
            uint totalLen = (uint)(tcpLen + padding);
            
            lock (writer)
            {
                // pcapng block header
                writer.Write((UInt32)0x00000006);          // block type
                writer.Write((UInt32)(32 + totalLen));     // block length
                writer.Write((UInt32)0);                   // interface ID
                writer.Write((UInt32)(time >> 32));        // timestamp (high)
                writer.Write((UInt32)(time & 0xFFFFFFFF)); // timestamp (low)
                writer.Write((UInt32)tcpLen);              // captured len
                writer.Write((UInt32)tcpLen);              // packet len

                // IPV4 header
                writer.Write((byte)0x45); // basic IP header
                writer.Write((byte)0x00);
                writer.Write((byte)(tcpLen >> 8));
                writer.Write((byte)(tcpLen & 0xFF));
                writer.Write((UInt32)0x00000000);
                writer.Write((byte)0x80); // TTL
                writer.Write((byte)0x11); // UDP
                UInt16 checksum = (UInt16)~(0x4500 + tcpLen + 0x8011 + (srcIP >> 16) + (srcIP & 0xFFFF) + (dstIP >> 16) + (dstIP & 0xFFFF));
                writer.Write((byte)(checksum >> 8));
                writer.Write((byte)(checksum & 0xFF));
                writer.Write((byte)(srcIP >> 24));
                writer.Write((byte)((srcIP >> 16) & 0xFF));
                writer.Write((byte)((srcIP >> 8) & 0xFF));
                writer.Write((byte)(srcIP & 0xFF));
                writer.Write((byte)(dstIP >> 24));
                writer.Write((byte)((dstIP >> 16) & 0xFF));
                writer.Write((byte)((dstIP >> 8) & 0xFF));
                writer.Write((byte)(dstIP & 0xFF));

                // UDP header
                writer.Write((byte)(srcPort >> 8));
                writer.Write((byte)(srcPort & 0xFF));
                writer.Write((byte)(dstPort >> 8));
                writer.Write((byte)(dstPort & 0xFF));
                writer.Write((byte)(udpLen >> 8));
                writer.Write((byte)(udpLen & 0xFF));
                writer.Write((UInt16)0x0000);

                // payload
                writer.Write(packet, offset, length);
                writer.Write(new byte[] { 0, 0, 0, 0 }, 0, padding);

                // pcapng block footer
                writer.Write((UInt32)(32 + totalLen));     // block length

                writer.Flush();
            }
        }
        
        private BinaryWriter writer;
        private ManualResetEvent headerWritten = new ManualResetEvent(false);
    }
}
