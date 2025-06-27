using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.Models;

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
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("Default-Connection"));

            _context = new RouterDetectorContext(optionsBuilder.Options);
            _context.Database.EnsureCreated(); // Creates DB if not exists
        }

        public async Task LogEvent(EventLog log)
        {
            _context.EventLogs.Add(log);
            await _context.SaveChangesAsync();
        }
    }
}