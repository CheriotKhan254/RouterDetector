using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.CaptureConsole.Utilities;
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
            var database = DatabaseService.CreateForConsole();

            // Subscribe to packet events
            captureService.OnPacketCaptured += async (packet) =>
            {
                try
                {
                    // Perform analysis
                    var threat = engine.AnalyzePacket(packet);
                    if (threat != null)
                    {
                        await LogThreatAsync(threat, captureService.SelectedDeviceDescription, database); // Use async method
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

            // Try to resolve hostname for source IP
            string? srcHostname = null;
            try { srcHostname = System.Net.Dns.GetHostEntry(threat.OriginalPacket.SourceIp?.ToString() ?? "").HostName; } catch { }
            // Try to resolve hostname for destination IP
            string? dstHostname = null;
            try { dstHostname = System.Net.Dns.GetHostEntry(threat.OriginalPacket.DestinationIp?.ToString() ?? "").HostName; } catch { }

            // Save threat and packet details to EventLog
            var eventLog = new RouterDetector.Models.EventLog
            {
                Timestamp = eatTime,
                Institution = LoadDevices.GetWifiRouterName() ?? "Unknown Network",
                DeviceName = deviceDescription,
                DeviceType = deviceDescription,
                LogSource = threat.ProtocolName,
                EventType = threat.ThreatDescription,
                Severity = threat.Severity.ToString(),
                Username = Environment.UserName, // Set if available
                SrcIp = threat.OriginalPacket.SourceIp?.ToString(),
                DstIp = threat.OriginalPacket.DestinationIp?.ToString(),
                SrcPort = threat.OriginalPacket.SourcePort,
                DstPort = threat.OriginalPacket.DestinationPort,
                Protocol = threat.OriginalPacket.TransportProtocol.ToString(),
                ActionTaken = "Logged",
                NatSrcIp = threat.OriginalPacket.SourceIp?.ToString(), // Set if available
                NatDstIp = threat.OriginalPacket.DestinationIp?.ToString(), // Set if available
                Hostname = Environment.MachineName, // Set if available
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
            Console.WriteLine("Threat and packet details saved to database.");
        }
    }
}