using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.ProtocolParsers;
using System.Collections.Generic;
using System.Text;
using System;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class SuspiciousEmailDetector : IDetector
    {
        public string ProtocolName => "Suspicious Email";

        private static readonly List<ushort> EmailPorts = new List<ushort> { 25, 110, 143, 465, 587, 993, 995 };
        private static readonly List<string> SuspiciousExtensions = new List<string>
        {
            ".exe", ".vbs", ".scr", ".bat", ".com", ".pif", ".cmd", ".js", ".jar", ".msi"
        };

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            if (!EmailPorts.Contains(packet.SourcePort) && !EmailPorts.Contains(packet.DestinationPort))
                return null;
            if (packet.Payload == null || packet.Payload.Length == 0)
                return null;

            string payloadString;
            try
            {
                payloadString = Encoding.ASCII.GetString(packet.Payload);
            }
            catch (ArgumentException)
            {
                return null;
            }

            // Use protocol parsers for deeper inspection
            EmailMessage? email = null;
            if (packet.SourcePort == 25 || packet.DestinationPort == 25 || packet.SourcePort == 465 || packet.DestinationPort == 465 || packet.SourcePort == 587 || packet.DestinationPort == 587)
            {
                email = new SmtpParser().Parse(payloadString);
            }
            else if (packet.SourcePort == 110 || packet.DestinationPort == 110 || packet.SourcePort == 995 || packet.DestinationPort == 995)
            {
                email = new Pop3Parser().Parse(payloadString);
            }
            else if (packet.SourcePort == 143 || packet.DestinationPort == 143 || packet.SourcePort == 993 || packet.DestinationPort == 993)
            {
                email = new ImapParser().Parse(payloadString);
            }

            if (email != null)
            {
                foreach (var att in email.Attachments)
                {
                    foreach (var ext in SuspiciousExtensions)
                    {
                        if (att.FileName != null && att.FileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        {
                            return new DetectionResult(
                                isThreat: true,
                                packet: packet,
                                description: $"Suspicious email attachment detected (filename: {att.FileName})",
                                severity: ThreatSeverity.Medium,
                                protocolName: ProtocolName
                            );
                        }
                    }
                }
            }

            // Fallback: legacy detection
            foreach (var ext in SuspiciousExtensions)
            {
                int idx = payloadString.IndexOf("filename=\"");
                if (idx >= 0)
                {
                    int endIdx = payloadString.IndexOf('"', idx + 10);
                    if (endIdx > idx)
                    {
                        string filename = payloadString.Substring(idx + 10, endIdx - (idx + 10));
                        if (filename.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        {
                            return new DetectionResult(
                                isThreat: true,
                                packet: packet,
                                description: $"Suspicious email attachment detected (filename: {filename})",
                                severity: ThreatSeverity.Medium,
                                protocolName: ProtocolName
                            );
                        }
                    }
                }
            }

            if (payloadString.Contains("base64", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var ext in SuspiciousExtensions)
                {
                    if (payloadString.Contains(ext, StringComparison.OrdinalIgnoreCase))
                    {
                        return new DetectionResult(
                            isThreat: true,
                            packet: packet,
                            description: $"Suspicious base64-encoded attachment detected (extension: {ext})",
                            severity: ThreatSeverity.Medium,
                            protocolName: ProtocolName
                        );
                    }
                }
            }

            return null;
        }
    }
}