using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Data;
using RouterDetector.Models;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
        private static readonly TimeZoneInfo EatZone = TimeZoneInfo.FindSystemTimeZoneById("E. Africa Standard Time");

        static void Main(string[] args)
        {
            CapturePacketsService captureService = new();
            DetectionEngine engine = new();
            DatabaseService database = new();

            // Subscribe to packet events
            captureService.OnPacketCaptured += async (packet) =>
            {
                try
                {
                    // Perform analysis
                    var threat = engine.AnalyzePacket(packet);
                    if (threat != null)
                    {
                        await LogThreatAsync(threat, "Unknown Device", database); // Use async method
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Packet analysis failed: {ex.Message}");
                }
            };

            try
            {
                captureService.StartService();
                Console.WriteLine("Press Enter to exit");
                Console.ReadKey();
            }
            finally
            {
                captureService.StopService();
            }
        }

        private static async Task LogThreatAsync(DetectionResult threat, string? deviceDescription, DatabaseService database)
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
            Console.ResetColor();

            Console.WriteLine($"Source: {threat.OriginalPacket.SourceIp}");
            Console.WriteLine($"Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}");

            // Save threat and packet details to EventLog
            var eventLog = new RouterDetector.Models.EventLog
            {
                Timestamp = eatTime,
                Institution = null, // Set if available
                DeviceName = deviceDescription,
                DeviceType = deviceDescription,
                LogSource = threat.ProtocolName,
                EventType = threat.ThreatDescription,
                Severity = threat.Severity.ToString(),
                Username = null, // Set if available
                SrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                DstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                SrcPort = threat.OriginalPacket.SourcePort,
                DstPort = threat.OriginalPacket.DestinationPort,
                Protocol = threat.OriginalPacket.TransportProtocol.ToString(),
                ActionTaken = "Logged",
                NatSrcIp = null, // Set if available
                NatDstIp = null, // Set if available
                Hostname = null, // Set if available
                Notes = $"Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}",
                RuleType = threat.ProtocolName,
                LivePcap = "true",
                Message = threat.ThreatDescription,
                LogOccurrence = eatTime.ToString("o"),
                EventType2 = null,
                Severity2 = null,
                UserAccount = null,
                ActionTaken2 = null
            };
            await database.LogEvent(eventLog);
            Console.WriteLine("Threat and packet details saved to database.");
        }
    }
}