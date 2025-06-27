using Microsoft.EntityFrameworkCore;
using RouterDetector.CaptureConsole.Models;

namespace RouterDetector.Data
{
    public class RouterDetectorContext : DbContext
    {
        public RouterDetectorContext(DbContextOptions<RouterDetectorContext> options)
            : base(options)
        {
        }

        // Removed: public DbSet<Detectionlogs> Detectionlogs { get; set; } = default!;
        // Removed: public DbSet<Networklogs> Networklogs { get; set; } = default!;
        public DbSet<EventLog> EventLogs { get; set; } = default!;
        // User model not needed in console
    }
}