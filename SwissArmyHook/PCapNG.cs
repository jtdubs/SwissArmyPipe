using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SwissArmyHook
{
    public class PCapNGWriter
    {
        public PCapNGWriter(BinaryWriter writer)
        {
            this.writer = writer;
            WriteSectionHeaderBlock();
            WriteInterfaceDescriptorBlock();
        }

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

        private void WriteInterfaceDescriptorBlock()
        {
            writer.Write((UInt32)0x00000001);    // block type
            writer.Write((UInt32)52);            // block length
            writer.Write((UInt16)206);           // LINKTYPE_FRELAY_WITH_DIR
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

        public void WriteEnhancedPacketBlock(bool sent, byte[] packet)
        {
            lock (writer)
            {
                ulong time = (ulong)((DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds * 1000);
                int padding = (4 - ((packet.Length + 1) % 4)) % 4;

                writer.Write((UInt32)0x00000006);                         // block type
                writer.Write((UInt32)(32 + packet.Length + 1 + padding)); // block length
                writer.Write((UInt32)0);                                  // interface ID
                writer.Write((UInt32)(time >> 32));                       // timestamp (high)
                writer.Write((UInt32)(time & 0xFFFFFFFF));                // timestamp (low)
                writer.Write((UInt32)packet.Length + 1);                  // captured len
                writer.Write((UInt32)packet.Length + 1);                  // packet len
                writer.Write((byte)(sent ? 1 : 0));
                writer.Write(packet);
                writer.Write(new byte[] { 0, 0, 0, 0 }, 0, padding);
                writer.Write((UInt32)(32 + packet.Length + 1 + padding)); // block length
                writer.Flush();
            }
        }

        public void WriteSimplePacketBlock(bool sent, byte[] packet)
        {
            lock (writer)
            {
                int padding = (4 - (packet.Length + 1 % 4)) % 4;

                writer.Write((UInt32)0x00000003);                         // block type
                writer.Write((UInt32)(16 + packet.Length + 1 + padding)); // block length
                writer.Write((UInt32)packet.Length + 1);                  // packet len
                writer.Write((byte)(sent ? 1 : 0));
                writer.Write(packet);
                writer.Write(new byte[] { 0, 0, 0, 0 }, 0, padding);
                writer.Write((UInt32)(16 + packet.Length + 1 + padding)); // block length
                writer.Flush();
            }
        }
        
        private BinaryWriter writer;
    }
}
