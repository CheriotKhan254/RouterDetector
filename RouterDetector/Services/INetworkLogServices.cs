using RouterDetector.Models;

namespace RouterDetector.Services
{
    public class NetworkTrafficCaptureService : BackgroundService
    {
        private readonly INetworkCaptureService _captureService;
        private readonly ILogger<NetworkTrafficCaptureService> _logger;

        public NetworkTrafficCaptureService(
            INetworkCaptureService captureService,
            ILogger<NetworkTrafficCaptureService> logger)
        {
            _captureService = captureService;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Network Traffic Capture Service is starting");

            try
            {
                await _captureService.StartCaptureAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start network capture");
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }

            await _captureService.StopCaptureAsync();
            _logger.LogInformation("Network Traffic Capture Service is stopping");
        }
    }
}
