using Microsoft.AspNetCore.Mvc;
using RouterDetector.Models;
using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using RouterDetector.Data;
using Microsoft.EntityFrameworkCore;

namespace RouterDetector.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly RouterDetectorContext _context;

        public HomeController(ILogger<HomeController> logger, RouterDetectorContext context)
        {
            _logger = logger;
            _context = context;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public async Task<IActionResult> Dashboard()
        {
            // Network logs analytics
            var totalNetworkLogs = await _context.Networklogs.CountAsync();
            var topSourceIps = await _context.Networklogs
                .GroupBy(l => l.SrcIp)
                .OrderByDescending(g => g.Count())
                .Select(g => new { Ip = g.Key, Count = g.Count() })
                .Take(5)
                .ToListAsync();
            var topProtocols = await _context.Networklogs
                .GroupBy(l => l.Protocol)
                .OrderByDescending(g => g.Count())
                .Select(g => new { Protocol = g.Key, Count = g.Count() })
                .Take(5)
                .ToListAsync();

            // Detection logs analytics
            var totalDetectionLogs = await _context.Detectionlogs.CountAsync();
            var topDeviceTypes = await _context.Detectionlogs
                .GroupBy(l => l.DeviceType)
                .OrderByDescending(g => g.Count())
                .Select(g => new { DeviceType = g.Key, Count = g.Count() })
                .Take(5)
                .ToListAsync();

            // Detection logs by event type
            var topEventTypes = await _context.Detectionlogs
                .GroupBy(l => l.EventType)
                .OrderByDescending(g => g.Count())
                .Select(g => new { EventType = g.Key, Count = g.Count() })
                .Take(5)
                .ToListAsync();

            // Network logs by destination IP
            var topDestIps = await _context.Networklogs
                .GroupBy(l => l.DstIp)
                .OrderByDescending(g => g.Count())
                .Select(g => new { Ip = g.Key, Count = g.Count() })
                .Take(5)
                .ToListAsync();

            // Recent activity
            var recentNetworkLogs = await _context.Networklogs
                .OrderByDescending(l => l.LogOccurrence)
                .Take(10)
                .ToListAsync();
            var recentDetectionLogs = await _context.Detectionlogs
                .OrderByDescending(l => l.Timestamp)
                .Take(10)
                .ToListAsync();

            ViewBag.TotalNetworkLogs = totalNetworkLogs;
            ViewBag.TopSourceIps = topSourceIps;
            ViewBag.TopProtocols = topProtocols;
            ViewBag.TotalDetectionLogs = totalDetectionLogs;
            ViewBag.TopDeviceTypes = topDeviceTypes;
            ViewBag.TopEventTypes = topEventTypes;
            ViewBag.TopDestIps = topDestIps;
            ViewBag.RecentNetworkLogs = recentNetworkLogs;
            ViewBag.RecentDetectionLogs = recentDetectionLogs;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
