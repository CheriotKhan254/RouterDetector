using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System;
using System.Collections.Generic;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class DdosDetector : IDetector
    {
        public string ProtocolName => "DDoS Attack";
        private readonly Dictionary<IPAddress, List<DateTime>> _targetHits = new();
        private readonly int _threshold = 100; // packets
        private readonly int _windowSeconds = 10;

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (packet.DestinationIp == null)
                return null;
            var now = DateTime.UtcNow;
            if (!_targetHits.ContainsKey(packet.DestinationIp))
                _targetHits[packet.DestinationIp] = new List<DateTime>();
            _targetHits[packet.DestinationIp].Add(now);
            _targetHits[packet.DestinationIp].RemoveAll(t => (now - t).TotalSeconds > _windowSeconds);
            if (_targetHits[packet.DestinationIp].Count >= _threshold)
            {
                return new DetectionResult(true, packet, $"Possible DDoS attack detected on {packet.DestinationIp} [DDoS]", ThreatSeverity.Critical, ProtocolName);
            }
            return null;
        }
    }
}