using System.Net;
using System.Net.NetworkInformation;

namespace RouterDetector.CaptureConsole.Models
{

    public class NetworkPacket
    {
        // Packet metadata
        public DateTime Timestamp { get; set; }
        public PhysicalAddress? SourceMac { get; set; }
        public PhysicalAddress? DestinationMac { get; set; }

        // Network layer (IP)
        public IPAddress? SourceIp { get; set; }
        public IPAddress? DestinationIp { get; set; }
        public int Ttl { get; set; }
        public IPProtocolType Protocol { get; set; }  // TCP, UDP, etc.

        // Transport layer
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public TransportProtocol TransportProtocol { get; set; }

        // Application layer
        public byte?[]? Payload { get; set; }
        public int PayloadLength => Payload?.Length ?? 0;

        // Additional useful information
        public bool IsOutbound { get; set; }  // Relative to your machine
        public bool IsGatewayBound { get; set; } // Heading to default gateway

        public override string ToString()
        {
            var protocol = TransportProtocol switch
            {
                TransportProtocol.Tcp => "TCP",
                TransportProtocol.Udp => "UDP",
                TransportProtocol.Icmp => "ICMP",
                _ => Protocol.ToString()
            };

            return $"[{Timestamp:HH:mm:ss.fff}] {SourceIp}:{SourcePort} → {DestinationIp}:{DestinationPort} " +
                   $"{protocol} (TTL:{Ttl}, {PayloadLength} bytes)";
        }
        public string GetPayloadPreview(int maxLength = 32)
        {
            if (Payload == null || Payload.Length == 0)
                return "[Empty payload]";

            var length = Math.Min(maxLength, Payload.Length);
            return BitConverter.ToString(Payload.Take(length).Select(b => b ?? 0).ToArray())
                   .Replace("-", " ");
        }
    }

    // Supporting enums
    public enum IPProtocolType
    {
        TCP = 6,
        UDP = 17,
        ICMP = 1,
        Other = 0
    }

    public enum TransportProtocol
    {
        Tcp,
        Udp,
        Icmp,
        Unknown
    }

}
