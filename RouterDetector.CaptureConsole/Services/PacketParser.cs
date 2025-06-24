using PacketDotNet;
using RouterDetector.CaptureConsole.Models;
using SharpPcap;

namespace RouterDetector.CaptureConsole.Services
{
    public static class PacketParser
    {
        public static NetworkPacket Parse(RawCapture rawPacket)
        {
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ethPacket = packet.Extract<EthernetPacket>();
            var ipPacket = packet.Extract<IPPacket>();

            var networkPacket = new NetworkPacket
            {
                Timestamp = rawPacket.Timeval.Date,
                SourceMac = ethPacket?.SourceHardwareAddress,
                DestinationMac = ethPacket?.DestinationHardwareAddress,
                SourceIp = ipPacket?.SourceAddress,
                DestinationIp = ipPacket?.DestinationAddress,
                Ttl = ipPacket?.TimeToLive ?? 0,
                Protocol = (IPProtocolType)(ipPacket?.Protocol ?? 0),
            };

            // Parse Transport Layer (TCP/UDP/ICMP)
            switch (networkPacket.Protocol)
            {
                case IPProtocolType.TCP:
                    var tcpPacket = packet.Extract<TcpPacket>();
                    networkPacket.TransportProtocol = TransportProtocol.Tcp;
                    networkPacket.SourcePort = (ushort)(tcpPacket?.SourcePort ?? 0);
                    networkPacket.DestinationPort = (ushort)(tcpPacket?.DestinationPort ?? 0);
                    break;

                case IPProtocolType.UDP:
                    var udpPacket = packet.Extract<UdpPacket>();
                    networkPacket.TransportProtocol = TransportProtocol.Udp;
                    networkPacket.SourcePort = (ushort)(udpPacket?.SourcePort ?? 0);
                    networkPacket.DestinationPort = (ushort)(udpPacket?.DestinationPort ?? 0);
                    break;

                case IPProtocolType.ICMP:
                    networkPacket.TransportProtocol = TransportProtocol.Icmp;
                    break;
            }

            return networkPacket;
        }
    }
}
