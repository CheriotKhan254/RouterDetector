using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
        static void Main(string[] args)
        {

            CapturePacketsService captureService = new();
            DetectionEngine engine = new();




            // Subscribe to packet events
            captureService.OnPacketCaptured += (packet) =>
            {
                try
                {
                    // Log and analyze
                    Console.WriteLine($"[{packet.Timestamp:HH:mm:ss}] {packet.SourceIp} → {packet.DestinationIp}");
                    // Perform analysis
                    engine.AnalyzePacket(packet);

                    // OR Using Option 2 (first threat only)
                    var threat = engine.AnalyzePacket(packet);
                    if (threat != null)
                    {
                        LogThreat(threat);

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
            }


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
