using SharpPcap;
using System.Net.NetworkInformation;

namespace RouterDetector.CaptureConsole.Utilities
{
    public class LoadDevices
    {
        public static string? GetDefaultGateway()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                foreach (var netInterface in interfaces)
                {
                    Console.WriteLine($"Interface: {netInterface.Name}");
                    Console.WriteLine($"  Type: {netInterface.NetworkInterfaceType}");
                    Console.WriteLine($"  Status: {netInterface.OperationalStatus}");

                    var ipProps = netInterface.GetIPProperties();
                    if (ipProps == null)
                    {
                        Console.WriteLine("  No IP properties found.");
                        continue;
                    }

                    foreach (var gw in ipProps.GatewayAddresses)
                    {
                        Console.WriteLine($"  Gateway: {gw.Address}");
                    }
                }

                var gateway = interfaces
                    .Select(n => n.GetIPProperties())
                    .Where(ipProps => ipProps != null)
                    .SelectMany(ipProps => ipProps.GatewayAddresses)
                    .Where(gateway => gateway?.Address != null)
                    .OrderBy(gateway => gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    .Select(gateway => gateway.Address.ToString())
                    .FirstOrDefault();

                return gateway; // Will return null if none found
            }
            catch (NetworkInformationException ex)
            {
                Console.WriteLine($"NetworkInformationException: {ex.Message}");
                return null;
            }
        }

        public static ICaptureDevice? SelectDevice()
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found. Make sure you're running as administrator.");
                return null;
            }

            Console.WriteLine("\nAvailable network devices:");
            Console.WriteLine("".PadRight(50, '-'));

            for (int i = 0; i < devices.Count; i++)
            {
                Console.WriteLine($"{i}: {devices[i].Description}");
            }

            Console.Write("\nEnter device number: ");
            if (int.TryParse(Console.ReadLine(), out int selectedIndex) &&
                selectedIndex >= 0 && selectedIndex < devices.Count)
            {
                var selectedDevice = devices[selectedIndex];

                return selectedDevice;
            }

            Console.WriteLine("Invalid selection.");
            return null;
        }

    }




}
