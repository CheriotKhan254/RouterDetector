using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class HttpsVolumeDetector : IDetector
    {
        public string ProtocolName => "Anomalous HTTPS Volume";
        private readonly Dictionary<IPAddress, List<DateTime>> _connections = new();
        private readonly int _threshold = 100; // connections
        private readonly int _windowSeconds = 60; // within 1 minute

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // We only care about TCP traffic to the standard HTTPS port.
            if (packet.TransportProtocol != TransportProtocol.Tcp || packet.DestinationPort != 443)
            {
                return null;
            }

            if (packet.SourceIp == null)
            {
                return null;
            }

            var now = DateTime.UtcNow;
            var sourceIp = packet.SourceIp;

            // Initialize the list for a new IP
            if (!_connections.ContainsKey(sourceIp))
            {
                _connections[sourceIp] = new List<DateTime>();
            }

            // Record the current connection attempt
            _connections[sourceIp].Add(now);

            // Important: Remove old timestamps that are outside our time window to keep the list from growing forever.
            _connections[sourceIp].RemoveAll(t => (now - t).TotalSeconds > _windowSeconds);

            // Check if the connection count for this IP exceeds our threshold
            if (_connections[sourceIp].Count > _threshold)
            {
                // This IP is making too many connections. It's an anomaly.
                return new DetectionResult(
                    isThreat: true,
                    packet: packet,
                    description: $"Anomalous HTTPS connection volume detected from {sourceIp} ({_connections[sourceIp].Count} connections in {_windowSeconds}s)",
                    severity: ThreatSeverity.Medium,
                    protocolName: ProtocolName
                );
            }

            return null; // No threat detected
        }
    }
}