using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.Data;
using RouterDetector.Models;

namespace RouterDetector.CaptureConsole.ConsoleUI
{
    /// <summary>
    /// Handles the main console menu and user interaction.
    /// </summary>
    public static class ConsoleMenuManager
    {
        /// <summary>
        /// Shows the main menu, allowing the user to start packet capture, configure the system, or exit.
        /// </summary>
        public static async Task ShowMainMenu(
            DatabaseService database,
            SystemConfigurationService configService,
            SystemConfigurationConsoleUI configUI,
            DetectionEngine engine,
            CapturePacketsService captureService,
            SystemConfiguration config)
        {
            bool exit = false;
            while (!exit)
            {
                Console.Clear();
                Console.WriteLine("=== Main Menu ===");
                Console.WriteLine("1. Start Packet Capture");

                Console.WriteLine("2. System Configuration");
                Console.WriteLine("3. Exit");
                Console.Write("Select an option: ");
                switch (Console.ReadLine())
                {
                    case "1":
                        // Centralized capture logic
                        await Program.RunPacketCaptureLoopAsync(database, engine, captureService, config.InstitutionName, config.StaffPosition);
                        break;
                    case "2":
                        await configUI.ShowMenuAsync();
                        break;
                    case "3":
                        exit = true;
                        break;
                    default:
                        Console.WriteLine("Invalid option. Press any key to continue...");
                        Console.ReadKey();
                        break;
                }
            }
            Console.WriteLine("Goodbye!");
        }
    }
}