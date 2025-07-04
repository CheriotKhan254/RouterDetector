using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Collections.Concurrent;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class BruteForceDetector : IDetector
    {
        public string ProtocolName => "Brute Force Attack";
        private readonly ConcurrentDictionary<IPAddress, LinkedList<DateTime>> _loginAttempts = new();
        private readonly Dictionary<ushort, int> _portThresholds;
        private readonly HashSet<ushort> _authPorts;
        private readonly int _windowSeconds;
        private readonly object _lock = new();
        private readonly HashSet<IPAddress> _whitelistedIPs;
        public BruteForceDetector(
            Dictionary<ushort, int> portThresholds,
            int windowSeconds,
            HashSet<IPAddress> whitelistedIPs)
        {
            _portThresholds = portThresholds;
            _windowSeconds = windowSeconds;
            _authPorts = new HashSet<ushort>
                { 22, 21, 23, 3389, 25, 110, 143, 587, 993, 995, 80, 443, 3306, 5432, 389, 636 };
            _whitelistedIPs = whitelistedIPs ?? new();
        }

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (!packet.IsInbound || !_authPorts.Contains(packet.DestinationPort))
                return null;
            if (packet.SourceIp == null)
                return null;

            if (_whitelistedIPs.Contains(packet.SourceIp))
                return null;

            var now = DateTime.UtcNow;
            var attempts = _loginAttempts.GetOrAdd(packet.SourceIp, _ => new LinkedList<DateTime>());

            lock (_lock)
            {
                attempts.AddLast(now);

                // Remove old attempts
                while (attempts.First != null && (now - attempts.First.Value).TotalSeconds > _windowSeconds)
                {
                    attempts.RemoveFirst();
                }

                int threshold = _portThresholds.GetValueOrDefault(packet.DestinationPort, 10);
                if (attempts.Count >= threshold)
                {
                    return new DetectionResult(
                        true,
                        packet,
                        $"Brute force attack detected from {packet.SourceIp} on port {packet.DestinationPort} ({attempts.Count} attempts in {_windowSeconds}s)",
                        ThreatSeverity.High,
                        ProtocolName
                    );
                }
            }

            return null;
        }

        public void ResetForIp(IPAddress ip)
        {
            _loginAttempts.TryRemove(ip, out _);
        }
    }
}