using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.ProtocolParsers;
using RouterDetector.CaptureConsole.Services;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class DnsBlacklistDetector : IDetector
    {
        public string ProtocolName => "DNS Blacklist";
        private readonly ThreatIntelService _threatIntelService;

        public DnsBlacklistDetector(ThreatIntelService threatIntelService)
        {
            _threatIntelService = threatIntelService;
        }

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // This detector only cares about DNS traffic.
            if (packet.PacketType != PacketType.DnsTraffic)
            {
                return null;
            }

            if (packet.Payload == null || packet.Payload.Length == 0)
            {
                return null;
            }

            var domains = DnsParser.GetQueriedDomains(packet.Payload);
            foreach (var domain in domains)
            {
                if (_threatIntelService.IsDomainBlacklisted(domain))
                {
                    return new DetectionResult(
                        isThreat: true,
                        packet: packet,
                        description: $"DNS query for known malicious domain: {domain}",
                        severity: ThreatSeverity.Critical,
                        protocolName: ProtocolName
                    );
                }
            }

            return null;
        }
    }
}