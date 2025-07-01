using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
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
                payloadString = Encoding.UTF8.GetString(packet.Payload);
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
}