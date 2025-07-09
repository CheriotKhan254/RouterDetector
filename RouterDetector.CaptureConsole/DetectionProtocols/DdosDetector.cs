using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class DdosDetector : IDetector
    {
        public string ProtocolName => "DDoS Attack";
        private readonly Dictionary<IPAddress, List<(IPAddress Source, DateTime Time)>> _targetHits = new();
        private readonly int _threshold;
        private readonly int _windowSeconds;
        private readonly int _sourceDiversityThreshold;
        private readonly HashSet<string> _allowedProtocols;
        private readonly HashSet<IPAddress> _whitelistedIPs;

        public DdosDetector(
            int packetThreshold,
            int windowSeconds,
            int sourceDiversityThreshold,
            HashSet<string> allowedProtocols,
            HashSet<IPAddress> whitelistedIPs)
        {
            _threshold = packetThreshold;
            _windowSeconds = windowSeconds;
            _sourceDiversityThreshold = sourceDiversityThreshold;
            _allowedProtocols = allowedProtocols ?? new();
            _whitelistedIPs = whitelistedIPs ?? new();
        }

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Only consider inbound packets (targeting this machine/network)
            if (!packet.IsInbound || packet.DestinationIp == null)
                return null;
            if (packet.SourceIp == null || _whitelistedIPs.Contains(packet.SourceIp))
                return null;
            if (!_allowedProtocols.Contains(packet.TransportProtocol.ToString()))
                return null;
            var now = DateTime.UtcNow;
            if (!_targetHits.ContainsKey(packet.DestinationIp))
                _targetHits[packet.DestinationIp] = new List<(IPAddress Source, DateTime Time)>();
            _targetHits[packet.DestinationIp].Add((packet.SourceIp, now));
            _targetHits[packet.DestinationIp].RemoveAll(t => (now - t.Time).TotalSeconds > _windowSeconds);

            if (_targetHits[packet.DestinationIp].Count >= _threshold)
            {
                return new DetectionResult(true, packet, $"Possible DDoS attack detected on {packet.DestinationIp} [DDoS]", ThreatSeverity.Critical, ProtocolName);
            }
            return null;
        }
    }


}