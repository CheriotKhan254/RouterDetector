using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.ProtocolParsers;
using RouterDetector.CaptureConsole.Services;
using System.Text;
using System.Text.RegularExpressions;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class PhishingDetector(ThreatIntelService threatIntelService) : IDetector
    {
        public string ProtocolName => "HTTP Phishing Detector";
        private readonly ThreatIntelService _threatIntelService = threatIntelService;

        // Regex to find URLs in payload. This is a simplified regex.

        private static readonly Regex UrlRegex = new Regex(@"(http|https|ftp)://([^\s/$.?#].[^\s]*)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Only scan TCP traffic going to port 80 (HTTP)
            if (packet.TransportProtocol != TransportProtocol.Tcp || packet.DestinationPort != 80)
                return null;

            var raw = packet.GetPayloadAsString(Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            if (HttpPayloadParser.TryParse(raw, out var method, out var headers, out var body))
            {
                // Check 1: Is the Host header on our blacklist?
                if (headers.TryGetValue("Host", out var host) && _threatIntelService.IsDomainBlacklisted(host))
                {
                    return new DetectionResult(
                        isThreat: true,
                        packet: packet,
                        description: $"Phishing attempt: HTTP request to known malicious host: {host} [Phishing]",
                        severity: ThreatSeverity.Critical,
                        protocolName: ProtocolName
                    );
                }

                // Check 2: Are plaintext credentials being sent?
                if (method == "POST" &&
                    headers.TryGetValue("Content-Type", out var ct) &&
                    ct.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    if (ContainsCredentialHints(body))
                    {
                        return new DetectionResult(
                            isThreat: true,
                            packet: packet,
                            description: "Suspicious email: Plaintext credentials detected over HTTP [Suspicious Email]",
                            severity: ThreatSeverity.Medium,
                            protocolName: ProtocolName
                        );
                    }
                }
            }

            return null;
        }

        private static bool ContainsCredentialHints(string body)
        {
            string[] keys = ["username", "password", "email", "login", "pass"];
            return keys.Any(k => body.Contains(k, StringComparison.OrdinalIgnoreCase));
        }
    }
}
