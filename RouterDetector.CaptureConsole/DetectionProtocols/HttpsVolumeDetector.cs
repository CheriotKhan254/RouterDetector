using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;
using System.Linq;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class HttpsVolumeDetector : IDetector
    {
        public string ProtocolName => "Anomalous HTTPS Volume";
        private readonly Dictionary<IPAddress, List<DateTime>> _connections = new();
        private readonly int _threshold;
        private readonly int _windowSeconds;
        private readonly TrafficDirection _direction;
        private readonly HashSet<IPAddress> _whitelistedIPs;
        private readonly HashSet<string> _whitelistedDomains;

        public HttpsVolumeDetector(int connectionThreshold, int windowSeconds, TrafficDirection direction, HashSet<IPAddress> whitelistedIPs, HashSet<string> whitelistedDomains)
        {
            _threshold = connectionThreshold;
            _windowSeconds = windowSeconds;
            _direction = direction;
            _whitelistedIPs = whitelistedIPs;
            _whitelistedDomains = whitelistedDomains;
        }
        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Direction check
            bool isInbound = packet.IsInbound;
            bool isOutbound = packet.IsOutbound;
            if ((_direction == TrafficDirection.Inbound && !isInbound) ||
                (_direction == TrafficDirection.Outbound && !isOutbound))
                return null;

            // We only care about TCP traffic to the standard HTTPS port.
            if (packet.TransportProtocol != TransportProtocol.Tcp || packet.DestinationPort != 443)
            {
                return null;
            }

            if (packet.SourceIp == null)
            {
                return null;
            }

            // Whitelist check
            if (_whitelistedIPs.Contains(packet.SourceIp))
                return null;
            // Optionally, check domain if available (not always possible at this layer)

            var now = DateTime.UtcNow;
            var sourceIp = packet.SourceIp;

            // Initialize the list for a new IP
            if (!_connections.ContainsKey(sourceIp))
            {
                _connections[sourceIp] = new List<DateTime>();
            }

            // Record the current connection attempt
            _connections[sourceIp].Add(now);

            // Remove old timestamps that are outside our time window
            _connections[sourceIp].RemoveAll(t => (now - t).TotalSeconds > _windowSeconds);

            // Check if the connection count for this IP exceeds our threshold
            if (_connections[sourceIp].Count > _threshold)
            {
                return new DetectionResult(
                    isThreat: true,
                    packet: packet,
                    description: $"Suspicious HTTPS connection volume detected from {sourceIp} ({_connections[sourceIp].Count} connections in {_windowSeconds}s) [Suspicious Activity]",
                    severity: ThreatSeverity.Medium,
                    protocolName: ProtocolName
                );
            }

            return null; // No threat detected
        }
    }
}