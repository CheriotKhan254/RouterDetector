using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class PhishingDetector : IDetector
    {
        public string ProtocolName => "Phishing Attempt";

        // Regex to find URLs in payload. This is a simplified regex.
        private static readonly Regex UrlRegex = new Regex(@"(http|https|ftp)://([^\s/$.?#].[^\s]*)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Phishing detection typically applies to web traffic.
            if (packet.TransportProtocol != TransportProtocol.Tcp || (packet.DestinationPort != 80 && packet.DestinationPort != 443))
            {
                return null;
            }

            if (packet.Payload == null || packet.Payload.Length == 0)
            {
                return null;
            }

            string payloadString;
            try
            {
                payloadString = Encoding.UTF8.GetString(packet.Payload.Where(b => b.HasValue).Select(b => b.Value).ToArray());
            }
            catch (ArgumentException)
            {
                return null; // Not a valid string, ignore.
            }

            var matches = UrlRegex.Matches(payloadString);
            foreach (Match match in matches)
            {
                var url = match.Value;
                // Example phishing check: URL contains an IP address instead of a domain name.
                // e.g., http://123.123.123.123/login.html
                if (Regex.IsMatch(url, @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                {
                    return new DetectionResult(
                        isThreat: true,
                        packet: packet,
                        description: $"Phishing detected: URL contains a suspicious IP address ({url})",
                        severity: ThreatSeverity.High,
                        protocolName: ProtocolName
                    );
                }

                // Add more checks here, e.g., for known malicious domains, URL shorteners, etc.
            }

            return null;
        }
    }
} 