using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RouterDetector.Models;
using System.IO;

namespace RouterDetector.Data
{
    public class DatabaseService
    {
        private readonly IDbContextFactory<RouterDetectorContext> _contextFactory;

        public DatabaseService(IDbContextFactory<RouterDetectorContext> contextFactory)
        {
            _contextFactory = contextFactory;
        }

        // Static factory method for console app
        public static DatabaseService CreateForConsole()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<RouterDetectorContext>();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("Default-Connection"));

            // We'll use a simple factory pattern here for the console app
            var factory = new ConsoleDbContextFactory(optionsBuilder.Options);

            return new DatabaseService(factory);
        }

        public async Task LogEvent(EventLog log)
        {
            using var context = _contextFactory.CreateDbContext();
            context.EventLogs.Add(log);
            await context.SaveChangesAsync();
        }
    }

    // Helper factory for the console application
    public class ConsoleDbContextFactory : IDbContextFactory<RouterDetectorContext>
    {
        private readonly DbContextOptions<RouterDetectorContext> _options;

        public ConsoleDbContextFactory(DbContextOptions<RouterDetectorContext> options)
        {
            _options = options;
        }

        public RouterDetectorContext CreateDbContext()
        {
            return new RouterDetectorContext(_options);
        }
    }
}