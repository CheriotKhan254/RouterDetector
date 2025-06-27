using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Data;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
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

        private static void LogThreat(DetectionResult threat)
        {
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

            // Optional detailed logging
            Console.WriteLine($"Source: {threat.OriginalPacket.SourceIp}");
            Console.WriteLine($"Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}");
        }
    }
}