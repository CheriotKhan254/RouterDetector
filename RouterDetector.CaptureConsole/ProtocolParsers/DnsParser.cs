using System.Collections.Generic;
using System.Text;

namespace RouterDetector.CaptureConsole.ProtocolParsers
{
    public static class DnsParser
    {
        public static List<string> GetQueriedDomains(byte[] payload)
        {
            var domains = new List<string>();
            if (payload == null || payload.Length < 13) // Basic check for DNS header
            {
                return domains;
            }

            try
            {
                // DNS header is 12 bytes. Questions start after that.
                int offset = 12;
                // QDCOUNT (Question Count) is at bytes 4-5
                int questionCount = (payload[4] << 8) | payload[5];

                for (int i = 0; i < questionCount; i++)
                {
                    var domain = ReadDomainName(payload, offset, out int newOffset);
                    if (!string.IsNullOrEmpty(domain))
                    {
                        domains.Add(domain);
                    }
                    // Move offset past the domain name and the QTYPE/QCLASS fields (4 bytes)
                    offset = newOffset + 4;
                }
            }
            catch
            {
                // If parsing fails, return what we have.
            }

            return domains;
        }

        private static string ReadDomainName(byte[] payload, int offset, out int newOffset)
        {
            var parts = new List<string>();
            int currentOffset = offset;
            int jumpedOffset = -1;

            while (currentOffset < payload.Length)
            {
                byte length = payload[currentOffset];

                // End of name marker
                if (length == 0)
                {
                    currentOffset++;
                    break;
                }

                // Check for pointer (compression)
                if ((length & 0xC0) == 0xC0)
                {
                    if (currentOffset + 1 >= payload.Length)
                    {
                        // Invalid pointer
                        newOffset = currentOffset + 1;
                        return string.Join(".", parts);
                    }

                    if (jumpedOffset == -1)
                    {
                        jumpedOffset = currentOffset + 2;
                    }

                    int pointer = ((length & 0x3F) << 8) | payload[currentOffset + 1];
                    currentOffset = pointer;
                    continue;
                }

                // It's a label
                currentOffset++;
                if (currentOffset + length > payload.Length)
                {
                    // Invalid length
                    break;
                }
                parts.Add(Encoding.ASCII.GetString(payload, currentOffset, length));
                currentOffset += length;
            }

            newOffset = (jumpedOffset != -1) ? jumpedOffset : currentOffset;
            return string.Join(".", parts);
        }
    }
}