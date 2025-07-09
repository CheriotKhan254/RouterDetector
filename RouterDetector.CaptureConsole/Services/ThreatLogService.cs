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

            var eventLog = new EventLog
            {
                Timestamp = eatTime,
                Institution = institutionName,
                DeviceName = deviceDescription,
                DeviceType = deviceDescription,
                LogSource = staffPosition,
                EventType = threat.ThreatDescription,
                Severity = threat.Severity.ToString(),
                Username = Environment.UserName,
                SrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                DstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                SrcPort = threat.OriginalPacket.SourcePort,
                DstPort = threat.OriginalPacket.DestinationPort,
                Protocol = threat.OriginalPacket.TransportProtocol.ToString(),
                ActionTaken = "Logged",
                NatSrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                NatDstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                Hostname = Environment.MachineName,
                Notes = $"Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}",
                RuleType = threat.ProtocolName,
                LivePcap = "true",
                Message = threat.ThreatDescription,
                LogOccurrence = eatTime.ToString("o"),
                EventType2 = threat.ProtocolName,
                Severity2 = threat.Severity.ToString(),
                UserAccount = $"{Environment.UserDomainName}\\{Environment.UserName}",
                ActionTaken2 = "Logged"
            };
            await database.LogEvent(eventLog);
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