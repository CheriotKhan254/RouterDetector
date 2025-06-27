using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace RouterDetector.CaptureConsole.Models
{
    public class NetworkPacket
    {
        // Packet metadata
        public DateTime Timestamp { get; set; }
        public PhysicalAddress? SourceMac { get; set; }
        public PhysicalAddress? DestinationMac { get; set; }
        public int PacketSize { get; set; }

        // Network layer (IP)
        public IPAddress? SourceIp { get; set; }
        public IPAddress? DestinationIp { get; set; }
        public int Ttl { get; set; }
        public IPProtocolType Protocol { get; set; }

        // Transport layer
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public TransportProtocol TransportProtocol { get; set; }

        // Protocol-specific info
        public TcpFlags TcpFlags { get; set; } = TcpFlags.None;
        public byte? IcmpType { get; set; }

        // Application layer
        public byte[]? Payload { get; set; }
        public int PayloadLength => Payload?.Length ?? 0;

        // Traffic analysis context
        public bool IsOutbound { get; set; }
        public bool IsInbound { get; set; }
        public bool IsInternal { get; set; }
        public PacketType PacketType { get; set; } = PacketType.Unknown;

        // Convenience properties
        public bool HasPayload => Payload != null && Payload.Length > 0;
        public bool IsTcpSyn => TransportProtocol == TransportProtocol.Tcp && TcpFlags.HasFlag(TcpFlags.Syn);
        public bool IsTcpConnection => TransportProtocol == TransportProtocol.Tcp &&
                                     (TcpFlags.HasFlag(TcpFlags.Syn) || TcpFlags.HasFlag(TcpFlags.Ack));

        public override string ToString()
        {
            var direction = IsOutbound ? "OUT" : IsInbound ? "IN" : IsInternal ? "INT" : "UNK";
            var protocol = TransportProtocol switch
            {
                TransportProtocol.Tcp => $"TCP{(TcpFlags != TcpFlags.None ? $"[{TcpFlags}]" : "")}",
                TransportProtocol.Udp => "UDP",
                TransportProtocol.Icmp => $"ICMP{(IcmpType.HasValue ? $"[{IcmpType}]" : "")}",
                _ => Protocol.ToString()
            };

            var ports = TransportProtocol == TransportProtocol.Icmp ? "" : $":{SourcePort} → :{DestinationPort}";

            return $"[{Timestamp:HH:mm:ss.fff}] {direction} {SourceIp}{ports} → {DestinationIp} " +
                   $"{protocol} (TTL:{Ttl}, {PayloadLength}b, {PacketType})";
        }

        public string GetPayloadPreview(int maxLength = 32)
        {
            if (Payload == null || Payload.Length == 0)
                return "[Empty payload]";

            var length = Math.Min(maxLength, Payload.Length);
            return BitConverter.ToString(Payload, 0, length).Replace("-", " ");
        }

        public string GetPayloadAsString(Encoding? encoding = null)
        {
            if (Payload == null || Payload.Length == 0)
                return string.Empty;

            encoding ??= Encoding.UTF8;

            try
            {
                return encoding.GetString(Payload);
            }
            catch
            {
                // Fallback to safe ASCII representation
                return Encoding.ASCII.GetString(Payload.Select(b => b < 32 || b > 126 ? (byte)'.' : b).ToArray());
            }
        }
    }

    // Supporting enums
    public enum IPProtocolType
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17,
        Other = 0
    }

    public enum TransportProtocol
    {
        Tcp,
        Udp,
        Icmp,
        Unknown
    }

    public enum PacketType
    {
        Unknown,
        TcpTraffic,
        UdpTraffic,
        IcmpTraffic,
        HttpTraffic,
        HttpsTraffic,
        DnsTraffic,
        DhcpTraffic,
        SshTraffic,
        TelnetTraffic,
        FtpTraffic,
        EmailTraffic,
        NtpTraffic,
        SnmpTraffic
    }
}