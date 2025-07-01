using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.CaptureConsole.Utilities;
using RouterDetector.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
        private static readonly TimeZoneInfo EatZone = TimeZoneInfo.FindSystemTimeZoneById("E. Africa Standard Time");

        static void Main(string[] args)
        {
            Console.WriteLine("Initializing RouterDetector...");

            // 1. Initialize detection engine (handles ThreatIntelService internally)
            DetectionEngine engine;
            try
            {
                engine = new DetectionEngine();
                Console.WriteLine("Detection engine (and threat intel): OK");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Detection engine (or threat intel) failed: {ex.Message}");
                Console.ResetColor();
                return;
            }

            // 2. Test database connection
            DatabaseService database;
            try
            {
                database = DatabaseService.CreateForConsole();
                // Test connection and read last EventLog
                using (var context = new RouterDetector.Data.RouterDetectorContext(
                    new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<RouterDetector.Data.RouterDetectorContext>()
                        .UseSqlServer(new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                            .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                            .AddJsonFile("appsettings.json")
                            .Build()
                            .GetConnectionString("Default-Connection"))
                        .Options))
                {
                    var lastLog = context.EventLogs
                        .OrderByDescending(e => e.Timestamp)
                        .FirstOrDefault();
                    if (lastLog != null)
                    {
                        Console.WriteLine($"Database connection: OK (Last log at {lastLog.Timestamp:yyyy-MM-dd HH:mm:ss})");
                    }
                    else
                    {
                        Console.WriteLine("Database connection: OK (No logs found)");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Database check failed: {ex.Message}");
                Console.ResetColor();
                return;
            }

            // 3. Print status and prompt
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("All systems initialized successfully.");
            Console.ResetColor();
            Console.WriteLine("Press Enter to start packet capturing...");
            Console.ReadLine();

            CapturePacketsService captureService = new();

            // Subscribe to packet events
            captureService.OnPacketCaptured += async (packet) =>
           {
               try
               {
                   // Analyze for threat
                   var threats = engine.AnalyzePacket(packet);
                   if (threats != null && threats.Any())
                   {
                       foreach (var t in threats)
                       {
                           var color = t.Severity switch
                           {
                               ThreatSeverity.Low => ConsoleColor.Yellow,
                               ThreatSeverity.Medium => ConsoleColor.DarkYellow,
                               ThreatSeverity.High => ConsoleColor.Red,
                               ThreatSeverity.Critical => ConsoleColor.Magenta,
                               _ => ConsoleColor.Gray
                           };
                           PrintPacketInfo(packet, color, t);
                           await LogThreatAsync(t, captureService.SelectedDeviceDescription, database);
                       }
                   }
                   else
                   {
                       // Print normal packet in cyan
                       PrintPacketInfo(packet, ConsoleColor.Cyan);
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
                Console.WriteLine("Press 'S' to stop capturing and review logs. Press 'Q' to quit.");

                bool capturing = true;
                while (true)
                {
                    var key = Console.ReadKey(true);
                    if (capturing && (key.Key == ConsoleKey.S))
                    {
                        captureService.StopService();
                        Console.WriteLine("Capture stopped. Press 'Q' to exit and close the window.");
                        capturing = false;
                    }
                    else if (!capturing && (key.Key == ConsoleKey.Q))
                    {
                        break;
                    }
                }
            }
            finally
            {
                // Ensure the service is stopped if not already
                captureService.StopService();
            }
        }

        private static void PrintPacketInfo(NetworkPacket packet, ConsoleColor color, DetectionResult? threat = null)
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

            Console.WriteLine($"Source: {threat.OriginalPacket.SourceIp} -> Destination: {threat.OriginalPacket.DestinationIp}:{threat.OriginalPacket.DestinationPort}");
            Console.WriteLine();

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

        }
    }
}