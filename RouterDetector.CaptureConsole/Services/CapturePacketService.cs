using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Utilities;
using SharpPcap;

namespace RouterDetector.CaptureConsole.Services
{
    public class CapturePacketsService
    {
        private string _gateway = string.Empty;
        private ICaptureDevice? _currentDevice;
        public string? SelectedDeviceDescription => _currentDevice?.Description;
        public event Action<NetworkPacket>? OnPacketCaptured; // Event for subscribers


        public void StartService()
        {
            try
            {
                if (InitializeDevices() && _currentDevice != null)
                {
                    _currentDevice.Open(DeviceModes.Promiscuous, 1000);
                    _currentDevice.OnPacketArrival += PacketHandler;
                    _currentDevice.StartCapture();
                }

            }

            catch (Exception ex)
            {
                Console.WriteLine($"Fatal error: {ex.Message}");
            }
        }



        public void StopService()
        {
            if (_currentDevice != null)
            {
                _currentDevice.StopCapture();
                _currentDevice.Close();
                Console.WriteLine("Capture stopped.");
            }
        }

        private void PacketHandler(object sender, PacketCapture receivedPacket)
        {
            try
            {
                var networkPacket = PacketParser.Parse(receivedPacket.GetPacket());
                if (networkPacket != null)
                {
                    OnPacketCaptured?.Invoke(networkPacket);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
        }



        private bool InitializeDevices()
        {
            _gateway = LoadDevices.GetDefaultGateway() ?? string.Empty;
            if (string.IsNullOrEmpty(_gateway))
            {
                Console.WriteLine("No default gateway found.");
                return false;
            }
            Console.WriteLine($"Gateway: {_gateway}");

            _currentDevice = LoadDevices.SelectDevice();
            if (_currentDevice == null)
            {
                Console.WriteLine("No capture device found.");
                return false;
            }
            Console.WriteLine($"Device Selected: {_currentDevice.Description}");

            return true;
        }
    }
}
