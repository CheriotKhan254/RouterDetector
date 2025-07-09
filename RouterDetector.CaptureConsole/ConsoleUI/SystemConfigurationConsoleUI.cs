// SystemConfigurationConsoleUI.cs
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Models;

namespace RouterDetector.CaptureConsole.ConsoleUI
{
    public class SystemConfigurationConsoleUI
    {
        private readonly SystemConfigurationService _configService;

        public SystemConfigurationConsoleUI(SystemConfigurationService configService)
        {
            _configService = configService;
        }

        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("System Configuration Manager");
                Console.WriteLine("1. View Current Configuration");
                Console.WriteLine("2. Add/Update Configuration");
                Console.WriteLine("3. Exit");
                Console.Write("Select an option: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        await ShowCurrentConfigAsync();
                        break;
                    case "2":
                        await AddOrUpdateConfigAsync();
                        break;
                    case "3":
                        return;
                    default:
                        Console.WriteLine("Invalid option. Press any key to continue...");
                        Console.ReadKey();
                        break;
                }
            }
        }

        private async Task ShowCurrentConfigAsync()
        {
            var config = await _configService.GetOrCreateDefaultAsync();

            Console.Clear();
            Console.WriteLine("=== Current Configuration ===");
            Console.WriteLine($"Institution: {config.InstitutionName}");
            Console.WriteLine($"Staff Position: {config.StaffPosition}");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

        private async Task AddOrUpdateConfigAsync()
        {
            Console.Clear();
            var currentConfig = await _configService.GetOrCreateDefaultAsync();

            Console.WriteLine("=== Update Configuration ===");
            Console.WriteLine("(Leave blank to keep current value)");

            Console.Write($"Institution Name [{currentConfig.InstitutionName}]: ");
            var institutionName = Console.ReadLine();

            Console.Write($"Staff Position [{currentConfig.StaffPosition}]: ");
            var staffPosition = Console.ReadLine();

            var updatedConfig = new SystemConfiguration
            {
                Id = currentConfig.Id,
                InstitutionName = string.IsNullOrWhiteSpace(institutionName)
                    ? currentConfig.InstitutionName
                    : institutionName,
                StaffPosition = string.IsNullOrWhiteSpace(staffPosition)
                    ? currentConfig.StaffPosition
                    : staffPosition
            };

            await _configService.UpdateAsync(updatedConfig);
            Console.WriteLine("Configuration updated successfully!");
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }
    }
}