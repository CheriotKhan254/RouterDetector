using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System.Collections.Generic;
using System.Text;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class SuspiciousEmailDetector : IDetector
    {
        public string ProtocolName => "Suspicious Email";

        private static readonly List<ushort> EmailPorts = new List<ushort> { 25, 110, 143, 465, 587, 993, 995 };
        
        // List of suspicious file extensions often used for malware in emails.
        private static readonly List<string> SuspiciousExtensions = new List<string>
        {
            ".exe", ".vbs", ".scr", ".bat", ".com", ".pif", ".cmd", ".js", ".jar", ".msi"
        };

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            // Check if the packet is on a common email port.
            if (!EmailPorts.Contains(packet.SourcePort) && !EmailPorts.Contains(packet.DestinationPort))
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
                // This is a very naive approach. Email content can be multipart, encoded (Base64), etc.
                // A real implementation would require a proper MIME parser.
                payloadString = Encoding.ASCII.GetString(packet.Payload.Where(b => b.HasValue).Select(b => b.Value).ToArray());
            }
            catch (ArgumentException)
            {
                return null;
            }
            
            // Look for filename="suspicious.exe" patterns.
            foreach (var ext in SuspiciousExtensions)
            {
                // This is a simplified check.
                if (payloadString.Contains($"filename=\"", StringComparison.OrdinalIgnoreCase) &&
                    payloadString.Contains(ext, StringComparison.OrdinalIgnoreCase))
                {
                     return new DetectionResult(
                        isThreat: true,
                        packet: packet,
                        description: $"Suspicious email attachment detected (extension: {ext})",
                        severity: ThreatSeverity.Medium,
                        protocolName: ProtocolName
                    );
                }
            }

            return null;
        }
    }
} 