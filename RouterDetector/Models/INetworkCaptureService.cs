namespace RouterDetector.Models
{
    // Update the interface to return CaptureDeviceInfo instead of string
    public interface INetworkCaptureService
    {
        Task StartCaptureAsync(string? deviceName = null);
        Task StopCaptureAsync();
        IEnumerable<CaptureDeviceInfo> GetAvailableDevices();
        bool IsRunning { get; }
        string? CurrentDevice { get; }
        string? RouterIp { get; }
    }
}
