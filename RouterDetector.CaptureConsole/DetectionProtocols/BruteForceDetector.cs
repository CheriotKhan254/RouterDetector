using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System;
using System.Collections.Generic;
using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class BruteForceDetector : IDetector
    {
        public string ProtocolName => "Brute Force Attack";
        private readonly Dictionary<IPAddress, List<DateTime>> _loginAttempts = new();
        private readonly int _threshold = 10; // attempts
        private readonly int _windowSeconds = 60;
        private readonly HashSet<ushort> _authPorts = new() { 22, 21, 23, 3389, 25, 110, 143, 587, 993, 995 };

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (!_authPorts.Contains(packet.DestinationPort))
                return null;
            if (packet.SourceIp == null)
                return null;
            var now = DateTime.UtcNow;
            if (!_loginAttempts.ContainsKey(packet.SourceIp))
                _loginAttempts[packet.SourceIp] = new List<DateTime>();
            _loginAttempts[packet.SourceIp].Add(now);
            _loginAttempts[packet.SourceIp].RemoveAll(t => (now - t).TotalSeconds > _windowSeconds);
            if (_loginAttempts[packet.SourceIp].Count >= _threshold)
            {
                return new DetectionResult(true, packet, $"Brute force attack immenent from {packet.SourceIp}", ThreatSeverity.High, ProtocolName);
            }
            return null;
        }
    }
}