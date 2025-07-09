using RouterDetector.CaptureConsole.ConsoleUI;
using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;
using RouterDetector.CaptureConsole.Utilities;
using RouterDetector.Data;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
        private static readonly TimeZoneInfo EatZone = TimeZoneInfo.FindSystemTimeZoneById("E. Africa Standard Time");




        static async Task Main(string[] args)
        {
            string routerName = LoadDevices.GetWifiRouterName() ?? "Unknown Network";

            Console.WriteLine("Initializing RouterDetector...");

            var (database, configService, configUI, engine, captureService, config) = await AppInitializer.InitializeAppAsync();

            if (database == null || configService == null || configUI == null || engine == null || captureService == null || config == null)
            {
                Console.WriteLine("Initialization failed. Press any key to exit.");
                Console.ReadKey();
                return;
            }

            string institutionName = config.InstitutionName;
            string staffPosition = config.StaffPosition;

            // Start packet capture loop (auto-start, with restart/stop logic)
            await RunPacketCaptureLoopAsync(database, engine, captureService, institutionName, staffPosition);

            // After user chooses to exit capture loop, show main menu
            await ConsoleMenuManager.ShowMainMenu(database, configService, configUI, engine, captureService, config);
        }

        public static Task RunPacketCaptureLoopAsync(DatabaseService database, DetectionEngine engine, CapturePacketsService captureService, string institutionName, string staffPosition)
        {
            while (true)
            {
                // Attach event handler
                async void Handler(NetworkPacket packet)
                {
                    try
                    {
                        var threats = engine.AnalyzePacket(packet);
                        if (threats != null && threats.Any())
                        {
                            foreach (var t in threats)
                            {
                                ThreatLogService.PrintThreatToConsole(t);
                                await ThreatLogService.SaveThreatToDatabaseAsync(t, captureService.SelectedDeviceDescription, database, institutionName, staffPosition);
                            }
                        }
                        else
                        {
                            ThreatLogService.PrintPacketInfo(packet, ConsoleColor.Cyan);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Packet analysis failed: {ex.Message}");
                    }
                }
                captureService.OnPacketCaptured += Handler;

                captureService.StartService();
                Console.WriteLine("Packet capture started. Press 'S' to stop.");
                bool stopped = false;
                while (!stopped)
                {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.S)
                    {
                        captureService.StopService();
                        stopped = true;
                        Console.WriteLine("Capture stopped. Press 'R' to restart, or any other key to return to menu...");
                        var nextKey = Console.ReadKey(true);
                        if (nextKey.Key == ConsoleKey.R)
                        {
                            // Detach handler before restarting
                            captureService.OnPacketCaptured -= Handler;
                            Console.Clear();
                            continue; // Restart capture
                        }
                        else
                        {
                            // Detach handler before exiting loop
                            captureService.OnPacketCaptured -= Handler;
                            Console.Clear();
                            break; // Exit to menu
                        }
                    }
                }
                break; // Exit the while(true) loop after one run
            }
            return Task.CompletedTask;
        }
    }
}

