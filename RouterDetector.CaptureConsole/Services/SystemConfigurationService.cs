// SystemConfigurationService.cs
using RouterDetector.Data;
using RouterDetector.Models;



namespace RouterDetector.CaptureConsole.Services
{
    public class SystemConfigurationService
    {
        private readonly DatabaseService _dbService;

        public SystemConfigurationService(DatabaseService dbService)
        {
            _dbService = dbService;
        }

        public async Task<SystemConfiguration?> GetByIdAsync(int id)
        {
            return await _dbService.GetSystemConfiguration(id);
        }

        public async Task<List<SystemConfiguration>> GetAllAsync()
        {
            return await _dbService.GetAllSystemConfigurations();
        }

        public async Task CreateAsync(SystemConfiguration config)
        {
            if (string.IsNullOrEmpty(config.InstitutionName))
                throw new ArgumentException("Institution name is required");

            await _dbService.AddSystemConfiguration(config);
        }

        public async Task UpdateAsync(SystemConfiguration config)
        {
            var existing = await GetByIdAsync(config.Id);
            if (existing == null)
                throw new KeyNotFoundException("Configuration not found");

            await _dbService.UpdateSystemConfiguration(config);
        }

        public async Task DeleteAsync(int id)
        {
            await _dbService.DeleteSystemConfiguration(id);
        }

        public async Task<string> GetInstitutionNameAsync()
        {
            var config = await _dbService.GetFirstSystemConfiguration();
            return config?.InstitutionName ?? "Default Institution";
        }

        public async Task<SystemConfiguration> GetOrCreateDefaultAsync()
        {
            var config = await _dbService.GetFirstSystemConfiguration();
            if (config == null)
            {
                config = new SystemConfiguration
                {
                    InstitutionName = "Default Institution",
                    StaffPosition = "Default Position"
                };
                await CreateAsync(config);
            }
            return config;
        }
    }
}