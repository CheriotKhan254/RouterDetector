using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RouterDetector.CaptureConsole.Models;

namespace RouterDetector.Data
{
    public class DatabaseService
    {
        private readonly RouterDetectorContext _context;

        public DatabaseService()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<RouterDetectorContext>();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));

            _context = new RouterDetectorContext(optionsBuilder.Options);
            _context.Database.EnsureCreated(); // Creates DB if not exists
        }

        public async Task LogDetection(DetectionResult result)
        {
            var log = new Detectionlogs
            {
                Timestamp = result.DetectionTime,
                SourceIP = result.OriginalPacket.SourceIp?.ToString(),
                // Map other fields as needed
                EventType = result.ThreatDescription,
                Severty = result.Severity.ToString(),
                ActionTaken = "Detected", // Default value
                Notes = $"Triggered by: {result.OriginalPacket.SourceIp}:{result.OriginalPacket.SourcePort}",
                Institution = "YourInstitution", // Set default or get from config
                DeviceType = "Network Device",
                LogSource = "RouterDetector"
            };

            _context.Detectionlogs.Add(log);
            await _context.SaveChangesAsync();
        }

        public async Task LogNetworkPacket(NetworkPacket packet)
        {
            var log = new Networklogs
            {
                SrcIp = packet.SourceIp?.ToString(),
                DstIp = packet.DestinationIp?.ToString(),
                SrcPort = packet.SourcePort,
                DstPort = packet.DestinationPort,
                Protocol = packet.Protocol.ToString(),
                LogOccurrence = packet.Timestamp,
                LivePcap = true, // Assuming live capture
                Message = $"Packet from {packet.SourceIp}:{packet.SourcePort}",
                RuleType = "Network Traffic" // Default value
            };

            _context.Networklogs.Add(log);
            await _context.SaveChangesAsync();
        }
    }
}