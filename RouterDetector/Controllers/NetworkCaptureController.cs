using Microsoft.AspNetCore.Mvc;
using RouterDetector.Models;

namespace RouterDetector.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class NetworkCaptureController : ControllerBase
    {
        private readonly INetworkCaptureService _captureService;

        public NetworkCaptureController(INetworkCaptureService captureService)
        {
            _captureService = captureService;
        }

        [HttpGet("devices")]
        public IActionResult GetAvailableDevices()
        {
            return Ok(_captureService.GetAvailableDevices());
        }

        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            return Ok(new
            {
                IsRunning = _captureService.IsRunning,
                CurrentDevice = _captureService.CurrentDevice,
                RouterIp = _captureService.RouterIp
            });
        }

        [HttpPost("start")]
        public async Task<IActionResult> StartCapture([FromBody] string? deviceName = null)
        {
            try
            {
                await _captureService.StartCaptureAsync(deviceName);
                return Ok();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("stop")]
        public async Task<IActionResult> StopCapture()
        {
            await _captureService.StopCaptureAsync();
            return Ok();
        }
    }
}
