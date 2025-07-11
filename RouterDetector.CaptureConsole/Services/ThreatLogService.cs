using RouterDetector.CaptureConsole.Models;
using RouterDetector.Data;
using RouterDetector.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace RouterDetector.CaptureConsole.Services
{
    /// <summary>
    /// Provides utilities for logging and displaying threat and packet information.
    /// </summary>
    public static class ThreatLogService
    {
        private static readonly TimeZoneInfo EatZone = TimeZoneInfo.FindSystemTimeZoneById("E. Africa Standard Time");

        /// <summary>
        /// Prints threat details to the console.
        /// </summary>
        public static void PrintThreatToConsole(DetectionResult threat)
        {
            var eatTime = TimeZoneInfo.ConvertTimeFromUtc(threat.DetectionTime.ToUniversalTime(), EatZone);
            var color = threat.Severity switch
            {
                ThreatSeverity.Low => ConsoleColor.Yellow,
                ThreatSeverity.Medium => ConsoleColor.DarkYellow,
                ThreatSeverity.High => ConsoleColor.Red,
                ThreatSeverity.Critical => ConsoleColor.Magenta,
                _ => ConsoleColor.Gray
            };

            Console.ForegroundColor = color;
            Console.WriteLine(threat.GetSummary());
            Console.WriteLine($"Source: {threat.OriginalPacket.SourceIp} -> Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}");
            Console.ResetColor();
            Console.WriteLine();
        }

        /// <summary>
        /// Saves threat details to the database.
        /// </summary>
        public static async Task SaveThreatToDatabaseAsync(DetectionResult threat, string? deviceDescription, DatabaseService database, string institutionName, string staffPosition)
        {
            var eatTime = TimeZoneInfo.ConvertTimeFromUtc(threat.DetectionTime.ToUniversalTime(), EatZone);
            // Try to resolve hostname for source IP
            string? srcHostname = null;
            try { srcHostname = System.Net.Dns.GetHostEntry(threat.OriginalPacket.SourceIp?.ToString() ?? "").HostName; } catch { }
            // Try to resolve hostname for destination IP
            string? dstHostname = null;
            try { dstHostname = System.Net.Dns.GetHostEntry(threat.OriginalPacket.DestinationIp?.ToString() ?? "").HostName; } catch { }

            // DEBUG: Print actual protocol and description
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[DEBUG] ProtocolName: {threat.ProtocolName} | ThreatDescription: {threat.ThreatDescription}");
            Console.ResetColor();

            // --- RULETYPE, MESSAGE, ACTIONTAKEN LOGIC BASED ON EVENT TYPE ---
            string ruleType, message, actionTaken;
            switch (threat.ProtocolName)
            {
                case "Port Scan":
                    ruleType = "Signature-based";
                    message = "Port scan detected";
                    break;
                case "Brute Force Attack":
                    ruleType = "Behavioral";
                    message = "Unauthorized access attempt";
                    break;
                case "HTTP Phishing Detector":
                    ruleType = "Signature-based";
                    message = "Phishing attempt detected";
                    break;
                case "DDoS Attack":
                    ruleType = "Behavioral";
                    message = "DDoS attack detected";
                    break;
                case "Web App Attack":
                    ruleType = "Behavioral";
                    message = "Web application attack detected";
                    break;
                case "Malware Detector":
                    ruleType = "Signature-based";
                    message = "Malware blocked";
                    break;
                default:
                    // Save the actual values if not matched
                    ruleType = threat.ProtocolName;
                    message = threat.ThreatDescription;
                    break;
            }
            actionTaken = threat.Severity switch
            {
                ThreatSeverity.Critical => "Blocked",
                ThreatSeverity.High => "Quarantined",
                ThreatSeverity.Medium => "Alerted",
                ThreatSeverity.Low => "Allowed",
                _ => "Logged"
            };

            // --- NOTES LOGIC BASED ON EVENT TYPE ---
            string notes;
            switch (threat.ProtocolName)
            {
                case "Port Scan":
                    notes = $"Port scan detected from {threat.OriginalPacket.SourceIp} to {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort} using {threat.OriginalPacket.TransportProtocol} at {eatTime}.";
                    break;
                case "Brute Force Attack":
                    notes = $"Brute force attack detected from {threat.OriginalPacket.SourceIp} on port {threat.OriginalPacket.DestinationPort} at {eatTime}.";
                    break;
                case "HTTP Phishing Detector":
                    notes = $"Phishing attempt detected from {threat.OriginalPacket.SourceIp} to {threat.OriginalPacket.DestinationIp} at {eatTime}.";
                    break;
                case "DDoS Attack":
                    notes = $"Possible DDoS attack on {threat.OriginalPacket.DestinationIp} from {threat.OriginalPacket.SourceIp} at {eatTime}.";
                    break;
                case "Web App Attack":
                    notes = $"Web application attack detected from {threat.OriginalPacket.SourceIp} to {threat.OriginalPacket.DestinationIp} at {eatTime}.";
                    break;
                default:
                    notes = $"Suspicious activity detected from {threat.OriginalPacket.SourceIp} to {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort} at {eatTime}.";
                    break;
            }

            // --- EVENTTYPE LOGIC BASED ON EVENT TYPE ---
            string eventType;
            switch (threat.ProtocolName)
            {
                case "Port Scan":
                    eventType = "Port Scan";
                    break;
                case "Brute Force Attack":
                    eventType = "Login Attempt";
                    break;
                case "HTTP Phishing Detector":
                    eventType = "Policy Violation";
                    break;
                case "DDoS Attack":
                    eventType = "Policy Violation";
                    break;
                case "Web App Attack":
                    eventType = "Policy Violation";
                    break;
                case "Malware Detector":
                    eventType = "Malware Detected";
                    break;
                default:
                    eventType = "Policy Violation";
                    break;
            }

            var eventLog = new EventLog
            {
                Timestamp = eatTime,
                Institution = institutionName,
                DeviceName = deviceDescription,
                DeviceType = deviceDescription,
                LogSource = staffPosition,
                EventType = eventType,
                Severity = threat.Severity.ToString(),
                Username = Environment.UserName,
                SrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                DstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                SrcPort = threat.OriginalPacket.SourcePort,
                DstPort = threat.OriginalPacket.DestinationPort,
                Protocol = threat.OriginalPacket.TransportProtocol.ToString(),
                ActionTaken = actionTaken,
                NatSrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                NatDstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                Hostname = Environment.MachineName,
                Notes = notes,
                RuleType = ruleType,
                Message = message,
                LivePcap = "true",
                LogOccurrence = eatTime.ToString("o"),
                EventType2 = eventType,
                Severity2 = threat.Severity.ToString(),
                UserAccount = $"{Environment.UserDomainName}\\{Environment.UserName}",
                ActionTaken2 = actionTaken
            };

            // Diagnostic logging
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[DEBUG] Attempting to save event log: {eventLog.Message} | {eventLog.EventType} | {eventLog.RuleType} | {eventLog.ActionTaken}");
            Console.ResetColor();
            try
            {
            await database.LogEvent(eventLog);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[DEBUG] Event log saved successfully.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Failed to save event log: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Prints a summary of a network packet to the console.
        /// </summary>
        public static void PrintPacketInfo(NetworkPacket packet, ConsoleColor color, DetectionResult? threat = null)
        {
            Console.ForegroundColor = color;
            string time = DateTime.Now.ToString("HH:mm:ss");
            string baseInfo = $"[{time}] {packet.SourceIp}:{packet.SourcePort} -> {packet.DestinationIp}:{packet.DestinationPort} [{packet.TransportProtocol}]";
            if (threat != null)
            {
                baseInfo += $" [{threat.Severity.ToString().ToUpper()}: {threat.ThreatDescription}]";
            }
            Console.WriteLine(baseInfo);
            Console.ResetColor();
        }
    }
}