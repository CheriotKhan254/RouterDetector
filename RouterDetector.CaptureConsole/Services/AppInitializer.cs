using RouterDetector.CaptureConsole.ConsoleUI;
using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Data;
using RouterDetector.Models;
using System;
using System.Threading.Tasks;

namespace RouterDetector.CaptureConsole.Services
{
    /// <summary>
    /// Handles application startup and initialization of all core modules.
    /// </summary>
    public static class AppInitializer
    {
        /// <summary>
        /// Initializes the database, services, engine, capture service, and system configuration.
        /// Prints status for each module as it is initialized.
        /// </summary>
        public static async Task<(DatabaseService?, SystemConfigurationService?, SystemConfigurationConsoleUI?, DetectionEngine?, CapturePacketsService?, SystemConfiguration?)> InitializeAppAsync()
        {
            DatabaseService database = null;
            SystemConfigurationService configService = null;
            SystemConfigurationConsoleUI configUI = null;
            DetectionEngine engine = null;
            CapturePacketsService captureService = null;
            SystemConfiguration config = null;

            // 1. Database
            try
            {
                database = DatabaseService.CreateForConsole();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Database OK");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Database check failed: {ex.Message}");
                Console.ResetColor();
                return (null, null, null, null, null, null);
            }

            // 2. Services/UI
            configService = new SystemConfigurationService(database);
            configUI = new SystemConfigurationConsoleUI(configService);

            // 3. Engine and Capture Service
            try
            {
                engine = new DetectionEngine();
                captureService = new CapturePacketsService();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Engine OK");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Engine or Capture Service failed: {ex.Message}");
                Console.ResetColor();
                return (database, configService, configUI, null, null, null);
            }

            // 4. System Configuration
            try
            {
                do
                {
                    config = await configService.GetOrCreateDefaultAsync();
                    if (string.IsNullOrWhiteSpace(config.InstitutionName))
                    {
                        Console.WriteLine("No system configuration found. Please set up configuration first.");
                        await configUI.ShowMenuAsync();
                    }
                } while (string.IsNullOrWhiteSpace(config.InstitutionName));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("System Configurations OK");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"System configuration failed: {ex.Message}");
                Console.ResetColor();
                return (database, configService, configUI, engine, captureService, null);
            }

            return (database, configService, configUI, engine, captureService, config);
        }
    }
}