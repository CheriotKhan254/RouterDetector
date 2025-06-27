using PacketDotNet;
using RouterDetector.CaptureConsole.Models;
using SharpPcap;
using System.Net;

namespace RouterDetector.CaptureConsole.Services
{
    public static class PacketParser
    {
        public static NetworkPacket? Parse(RawCapture rawPacket)
        {
            try
            {
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ethPacket = packet.Extract<EthernetPacket>();
                var ipPacket = packet.Extract<IPPacket>();

                // Skip non-IP packets for now
                if (ipPacket == null)
                    return null;

                var networkPacket = new NetworkPacket
                {

                    Timestamp = DateTime.Now,
                    SourceMac = ethPacket?.SourceHardwareAddress,
                    DestinationMac = ethPacket?.DestinationHardwareAddress,
                    SourceIp = ipPacket.SourceAddress,
                    DestinationIp = ipPacket.DestinationAddress,
                    Ttl = ipPacket.TimeToLive,
                    Protocol = (IPProtocolType)(int)ipPacket.Protocol,
                    PacketSize = rawPacket.Data.Length
                };

                // Parse Transport Layer and extract payload
                ParseTransportLayer(packet, networkPacket);

                // Add some useful context
                DetermineDirection(networkPacket);
                DeterminePacketType(networkPacket);

                return networkPacket;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Parse Error]: {ex.Message}");
                return null;
            }

        }

        private static void ParseTransportLayer(Packet packet, NetworkPacket networkPacket)
        {
            switch (networkPacket.Protocol)
            {
                case IPProtocolType.TCP:
                    var tcpPacket = packet.Extract<TcpPacket>();
                    if (tcpPacket != null)
                    {
                        networkPacket.TransportProtocol = TransportProtocol.Tcp;
                        networkPacket.SourcePort = (ushort)tcpPacket.SourcePort;
                        networkPacket.DestinationPort = (ushort)tcpPacket.DestinationPort;
                        networkPacket.TcpFlags = GetTcpFlags(tcpPacket);
                        networkPacket.Payload = tcpPacket.PayloadData;
                    }
                    break;

                case IPProtocolType.UDP:
                    var udpPacket = packet.Extract<UdpPacket>();
                    if (udpPacket != null)
                    {
                        networkPacket.TransportProtocol = TransportProtocol.Udp;
                        networkPacket.SourcePort = (ushort)udpPacket.SourcePort;
                        networkPacket.DestinationPort = (ushort)udpPacket.DestinationPort;
                        networkPacket.Payload = udpPacket.PayloadData;
                    }
                    break;

                case IPProtocolType.ICMP:
                    var icmpPacket = packet.Extract<IcmpV4Packet>();
                    networkPacket.TransportProtocol = TransportProtocol.Icmp;
                    networkPacket.IcmpType = (byte?)(icmpPacket?.TypeCode);
                    networkPacket.Payload = icmpPacket?.PayloadData;
                    break;

                default:
                    networkPacket.TransportProtocol = TransportProtocol.Unknown;
                    // Try to get payload from IP packet
                    var ipPacket = packet.Extract<IPPacket>();
                    networkPacket.Payload = ipPacket?.PayloadData;
                    break;
            }
        }

        private static TcpFlags GetTcpFlags(TcpPacket tcpPacket)
        {
            TcpFlags flags = TcpFlags.None;

            if (tcpPacket.Finished) flags |= TcpFlags.Fin;
            if (tcpPacket.Synchronize) flags |= TcpFlags.Syn;
            if (tcpPacket.Reset) flags |= TcpFlags.Rst;
            if (tcpPacket.Push) flags |= TcpFlags.Psh;
            if (tcpPacket.Acknowledgment) flags |= TcpFlags.Ack;
            if (tcpPacket.Urgent) flags |= TcpFlags.Urg;
            if (tcpPacket.ExplicitCongestionNotificationEcho) flags |= TcpFlags.Ece;
            if (tcpPacket.CongestionWindowReduced) flags |= TcpFlags.Cwr;

            return flags;
        }


        private static void DetermineDirection(NetworkPacket packet)
        {
            // This is a simplified version - you'll want to replace with your actual local network detection
            if (packet.SourceIp != null && packet.DestinationIp != null)
            {
                var sourceIsLocal = IsLocalAddress(packet.SourceIp);
                var destIsLocal = IsLocalAddress(packet.DestinationIp);

                packet.IsOutbound = sourceIsLocal && !destIsLocal;
                packet.IsInbound = !sourceIsLocal && destIsLocal;
                packet.IsInternal = sourceIsLocal && destIsLocal;
            }
        }

        private static void DeterminePacketType(NetworkPacket packet)
        {
            // Classify common packet types based on ports and protocols
            if (packet.TransportProtocol == TransportProtocol.Tcp)
            {
                packet.PacketType = packet.DestinationPort switch
                {
                    80 or 8080 => PacketType.HttpTraffic,
                    443 or 8443 => PacketType.HttpsTraffic,
                    22 => PacketType.SshTraffic,
                    23 => PacketType.TelnetTraffic,
                    21 => PacketType.FtpTraffic,
                    25 or 587 or 465 => PacketType.EmailTraffic,
                    _ => PacketType.TcpTraffic
                };
            }
            else if (packet.TransportProtocol == TransportProtocol.Udp)
            {
                packet.PacketType = packet.DestinationPort switch
                {
                    53 => PacketType.DnsTraffic,
                    67 or 68 => PacketType.DhcpTraffic,
                    123 => PacketType.NtpTraffic,
                    161 or 162 => PacketType.SnmpTraffic,
                    _ => PacketType.UdpTraffic
                };
            }
            else if (packet.TransportProtocol == TransportProtocol.Icmp)
            {
                packet.PacketType = PacketType.IcmpTraffic;
            }
            else
            {
                packet.PacketType = PacketType.Unknown;
            }
        }

        private static bool IsLocalAddress(IPAddress address)
        {
            // Simple local network detection - you should enhance this based on your network setup
            var bytes = address.GetAddressBytes();

            return address.Equals(IPAddress.Loopback) ||
                   address.Equals(IPAddress.IPv6Loopback) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 10) ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31);
        }
    }



}