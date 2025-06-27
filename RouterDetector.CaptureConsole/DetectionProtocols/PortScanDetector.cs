using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class PortScanDetector(int portThreshold = 5, int timeWindowSeconds = 60) : IDetector
    {
        public string ProtocolName => "Port Scan";
        private readonly int _portThreshold = portThreshold;
        private readonly int _timeWindowSeconds = timeWindowSeconds;


        // Track recent port access per IP
        private readonly Dictionary<IPAddress, List<(ushort Port, DateTime Time)>> _accessHistory = [];

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            //only analyze TCP/UDP
            if (packet.TransportProtocol != TransportProtocol.Tcp &&
            packet.TransportProtocol != TransportProtocol.Udp)
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

            //remove entries older than 1 minute
            _accessHistory[sourceIp].RemoveAll(x =>
               (DateTime.UtcNow - x.Time).TotalSeconds > 60);

            //check scan thresholds
            var uniquePorts = _accessHistory[sourceIp]
                .Select(x => x.Port)
                .Distinct()
                .Count();

            if (uniquePorts >= 5)//Configure this later
            {
                return new DetectionResult(
                    isThreat: true,
                    packet: packet,
                    description: $"Port scan detected from {sourceIp} ({uniquePorts} unique ports)",
                    severity: ThreatSeverity.High,
                    protocolName: ProtocolName
                );
            }

            CleanupStaleEntries();
            return null;
        }

        private void CleanupStaleEntries()
        {
            var now = DateTime.UtcNow;
            var staleIps = _accessHistory
                .Where(kvp => kvp.Value.All(x => (now - x.Time).TotalSeconds > 60))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var ip in staleIps)
            {
                _accessHistory.Remove(ip);
            }
        }



    }
}