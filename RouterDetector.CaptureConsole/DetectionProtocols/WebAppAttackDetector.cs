using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
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
                payloadString = Encoding.UTF8.GetString(packet.Payload);
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