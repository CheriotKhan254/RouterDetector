using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    // 1. Brute Force Attack Detector
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
                return new DetectionResult(true, packet, $"Brute force attack detected from {packet.SourceIp}", ThreatSeverity.High, ProtocolName);
            }
            return null;
        }
    }

    // 2. DDoS Attack Detector
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
                return new DetectionResult(true, packet, $"Possible DDoS attack on {packet.DestinationIp}", ThreatSeverity.Critical, ProtocolName);
            }
            return null;
        }
    }

    // 3. System Attack Detector (simple signature-based)
    public class SystemAttackDetector : IDetector
    {
        public string ProtocolName => "System Attack";
        private static readonly List<string> SystemAttackSignatures = new()
        {
            "rootkit", "exploit", "buffer overflow", "privilege escalation", "shellcode", "ms17-010", "cve-"
        };
        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (packet.Payload == null || packet.Payload.Length == 0)
                return null;
            string payloadString;
            try
            {
                payloadString = Encoding.UTF8.GetString(packet.Payload.Where(b => b.HasValue).Select(b => b.Value).ToArray());
            }
            catch { return null; }
            foreach (var sig in SystemAttackSignatures)
            {
                if (payloadString.Contains(sig, StringComparison.OrdinalIgnoreCase))
                {
                    return new DetectionResult(true, packet, $"System attack signature detected: {sig}", ThreatSeverity.Critical, ProtocolName);
                }
            }
            return null;
        }
    }

    // 4. Mobile App Attack Detector (simple port/payload check)
    public class MobileAppAttackDetector : IDetector
    {
        public string ProtocolName => "Mobile App Attack";
        private static readonly HashSet<ushort> MobilePorts = new() { 5228, 5223, 2195, 2196, 5222, 443 };
        private static readonly List<string> MobileAttackPatterns = new() { "android malware", "ios exploit", "apk", "ipa", "mobile botnet" };
        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (!MobilePorts.Contains(packet.DestinationPort) && !MobilePorts.Contains(packet.SourcePort))
                return null;
            if (packet.Payload == null || packet.Payload.Length == 0)
                return null;
            string payloadString;
            try
            {
                payloadString = Encoding.UTF8.GetString(packet.Payload.Where(b => b.HasValue).Select(b => b.Value).ToArray());
            }
            catch { return null; }
            foreach (var pattern in MobileAttackPatterns)
            {
                if (payloadString.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return new DetectionResult(true, packet, $"Mobile app attack pattern detected: {pattern}", ThreatSeverity.High, ProtocolName);
                }
            }
            return null;
        }
    }

    // 5. Web App Attack Detector (simple regex for SQLi/XSS)
    public class WebAppAttackDetector : IDetector
    {
        public string ProtocolName => "Web App Attack";
        private static readonly Regex SqlInjectionRegex = new Regex(@"(['""]).*?(or|and)\s+\d+=\d+", RegexOptions.IgnoreCase);
        private static readonly Regex XssRegex = new Regex(@"<script.*?>.*?</script>", RegexOptions.IgnoreCase);
        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (packet.DestinationPort != 80 && packet.DestinationPort != 443)
                return null;
            if (packet.Payload == null || packet.Payload.Length == 0)
                return null;
            string payloadString;
            try
            {
                payloadString = Encoding.UTF8.GetString(packet.Payload.Where(b => b.HasValue).Select(b => b.Value).ToArray());
            }
            catch { return null; }
            if (SqlInjectionRegex.IsMatch(payloadString))
            {
                return new DetectionResult(true, packet, "Possible SQL Injection detected", ThreatSeverity.High, ProtocolName);
            }
            if (XssRegex.IsMatch(payloadString))
            {
                return new DetectionResult(true, packet, "Possible XSS attack detected", ThreatSeverity.High, ProtocolName);
            }
            return null;
        }
    }
}
