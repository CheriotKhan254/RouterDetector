using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Data;

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
                        LogThreat(threat);
                        await database.LogDetection(threat);
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

        private static void LogThreat(DetectionResult threat, RouterDetectorContext dbContext, string? deviceDescription)
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

            // Save threat to Detectionlogs
            var detectionLog = new Detectionlogs
            {
                Timestamp = eatTime,
                SourceIP = threat.OriginalPacket.SourceIp?.ToString(),
                DeviceType = deviceDescription,
                LogSource = threat.ProtocolName,
                EventType = threat.ThreatDescription,
                Severty = threat.Severity.ToString(),
                ActionTaken = "Logged",
                Notes = $"Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}"
            };
            dbContext.Detectionlogs.Add(detectionLog);

            // Save packet details to Networklogs
            var networkLog = new Networklogs
            {
                SrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                DstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                SrcPort = threat.OriginalPacket.SourcePort,
                DstPort = threat.OriginalPacket.DestinationPort,
                Protocol = threat.OriginalPacket.TransportProtocol.ToString(),
                RuleType = threat.ProtocolName,
                LivePcap = true,
                LogOccurrence = eatTime,
                Message = threat.ThreatDescription, 
            };
            dbContext.Networklogs.Add(networkLog);

            dbContext.SaveChanges();
            Console.WriteLine("Threat and packet details saved to database.");
        }
    }
}