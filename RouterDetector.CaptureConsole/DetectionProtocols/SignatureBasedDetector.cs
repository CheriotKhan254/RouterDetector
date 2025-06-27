using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Text;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class SignatureBasedDetector : IDetector
    {
        public string ProtocolName => "Signature-based Malware";

        private readonly Dictionary<string, (string MalwareName, ThreatSeverity Severity)> _signatures = new();

        public SignatureBasedDetector()
        {
            // Simple string-based signatures for demonstration
            // In a real-world scenario, these would be more complex (e.g., regex, binary patterns)
            // and loaded from a configuration file or database.
            _signatures.Add("malicious_payload_test", ("Test Malware", ThreatSeverity.High));
            _signatures.Add("worm_signature_example", ("Example Worm", ThreatSeverity.Critical));
            _signatures.Add("trojan_horse_pattern", ("Sample Trojan", ThreatSeverity.High));
        }

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (packet.Payload == null || packet.Payload.Length == 0)
            {
                return null;
            }

            // For simplicity, converting payload to a string. 
            // This is inefficient and might not work for binary protocols.
            // A real implementation would be more sophisticated.
            string payloadString;
            try
            {
                payloadString = Encoding.UTF8.GetString(packet.Payload);
            }
            catch (ArgumentException)
            {
                // Not a valid UTF8 string, could be binary data.
                // For this simple detector, we'll ignore it.
                return null;
            }


            foreach (var signature in _signatures)
            {
                if (payloadString.Contains(signature.Key, StringComparison.OrdinalIgnoreCase))
                {
                    var (malwareName, severity) = signature.Value;
                    return new DetectionResult(
                        isThreat: true,
                        packet: packet,
                        description: $"Malware detected: {malwareName} (signature: {signature.Key})",
                        severity: severity,
                        protocolName: ProtocolName
                    );
                }
            }

            return null;
        }
    }
} 