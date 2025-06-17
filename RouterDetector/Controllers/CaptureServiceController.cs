using Microsoft.AspNetCore.Mvc;
using RouterDetector.Models;

namespace RouterDetector.Controllers
{
    public class CaptureServiceController : Controller
    {
        private readonly INetworkCaptureService _captureService;

        public CaptureServiceController(INetworkCaptureService captureService)
        {
            _captureService = captureService;
        }


        public IActionResult Index()
        {
            return View();
        }
    }
}
