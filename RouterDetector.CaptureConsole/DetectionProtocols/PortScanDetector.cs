using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class PortScanDetector(int portThreshold = 5, int timeWindowSeconds = 60, HashSet<IPAddress>? whitelistedIPs = null) : IDetector
    {
        public string ProtocolName => "Port Scan";
        private readonly int _portThreshold = portThreshold;
        private readonly int _timeWindowSeconds = timeWindowSeconds;
        private readonly HashSet<IPAddress> _whitelistedIPs = whitelistedIPs ?? new();

        // Track recent port access per IP
        private readonly Dictionary<IPAddress, List<(ushort Port, DateTime Time)>> _accessHistory = [];

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Only consider inbound packets (targeting this machine/network)
            if (!packet.IsInbound)
                return null;

            //only analyze TCP/UDP
            if (packet.TransportProtocol != TransportProtocol.Tcp &&
            packet.TransportProtocol != TransportProtocol.Udp)
                return null;

            //check if source IP is whitelisted
            if (packet.SourceIp == null || _whitelistedIPs.Contains(packet.SourceIp))
                return null;

            var sourceIp = packet.SourceIp;
            if (sourceIp == null)
            {
                return null;
            }

            var destPort = packet.DestinationPort;

            //initialize history for new IPs
            if (!_accessHistory.ContainsKey(sourceIp))
            {
                _accessHistory[sourceIp] = new List<(ushort Port, DateTime Time)>();
            }

            //record this access
            _accessHistory[sourceIp].Add((destPort, DateTime.UtcNow));

            //remove entries older than the time window
            _accessHistory[sourceIp].RemoveAll(x =>
               (DateTime.UtcNow - x.Time).TotalSeconds > _timeWindowSeconds);

            //check scan thresholds
            var uniquePorts = _accessHistory[sourceIp]
                .Select(x => x.Port)
                .Distinct()
                .Count();

            if (uniquePorts >= _portThreshold)
            {
                CleanupStaleEntries();
                return new DetectionResult(
                    isThreat: true,
                    packet: packet,
                    description: $"Suspicious port scanning activity detected from {sourceIp} ({uniquePorts} unique ports) [Suspicious Attack]",
                    severity: ThreatSeverity.High,
                    protocolName: ProtocolName
                );
            }

            return null;
        }

        private void CleanupStaleEntries()
        {
            var now = DateTime.UtcNow;
            var staleIps = _accessHistory
                .Where(kvp => kvp.Value.All(x => (now - x.Time).TotalSeconds > _timeWindowSeconds))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var ip in staleIps)
            {
                _accessHistory.Remove(ip);
            }
        }



    }
}