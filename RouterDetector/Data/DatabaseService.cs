// DatabaseService.cs
using Microsoft.EntityFrameworkCore;
using RouterDetector.Models;

namespace RouterDetector.Data
{
    public class DatabaseService
    {
        private readonly IDbContextFactory<RouterDetectorContext> _contextFactory;

        public DatabaseService(IDbContextFactory<RouterDetectorContext> contextFactory)
        {
            _contextFactory = contextFactory;
        }

        public static DatabaseService CreateForConsole()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            var optionsBuilder = new DbContextOptionsBuilder<RouterDetectorContext>();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("Default-Connection"));

            var factory = new ConsoleDbContextFactory(optionsBuilder.Options);
            return new DatabaseService(factory);
        }

        // SystemConfiguration CRUD Operations
        public async Task AddSystemConfiguration(SystemConfiguration config)
        {
            using var context = _contextFactory.CreateDbContext();
            context.SystemConfiguration.Add(config);
            await context.SaveChangesAsync();
        }

        public async Task<SystemConfiguration?> GetSystemConfiguration(int id)
        {
            using var context = _contextFactory.CreateDbContext();
            return await context.SystemConfiguration.FindAsync(id);
        }

        public async Task<List<SystemConfiguration>> GetAllSystemConfigurations()
        {
            using var context = _contextFactory.CreateDbContext();
            return await context.SystemConfiguration.ToListAsync();
        }

        public async Task UpdateSystemConfiguration(SystemConfiguration config)
        {
            using var context = _contextFactory.CreateDbContext();
            context.SystemConfiguration.Update(config);
            await context.SaveChangesAsync();
        }

        public async Task DeleteSystemConfiguration(int id)
        {
            using var context = _contextFactory.CreateDbContext();
            var config = await context.SystemConfiguration.FindAsync(id);
            if (config != null)
            {
                context.SystemConfiguration.Remove(config);
                await context.SaveChangesAsync();
            }
        }

        public async Task<SystemConfiguration?> GetFirstSystemConfiguration()
        {
            using var context = _contextFactory.CreateDbContext();
            return await context.SystemConfiguration.FirstOrDefaultAsync();
        }

        // Original logging method
        public async Task LogEvent(EventLog log)
        {
            using var context = _contextFactory.CreateDbContext();
            context.EventLogs.Add(log);
            await context.SaveChangesAsync();
        }
    }

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