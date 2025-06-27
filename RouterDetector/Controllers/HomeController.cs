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
            var allDetections = await _context.Detectionlogs.ToListAsync();
            var totalNetworkLogs = await _context.Networklogs.CountAsync();

            var malwareDetections = allDetections
                .Where(d => d.EventType != null && (
                    d.EventType.Contains("Malware detected") ||
                    d.EventType.Contains("Worm") ||
                    d.EventType.Contains("Trojan")))
                .ToList();

            var phishingDetections = allDetections
                .Where(d => d.EventType != null && d.EventType.Contains("Phishing detected"))
                .ToList();
            
            var suspiciousEmailDetections = allDetections
                .Where(d => d.EventType != null && d.EventType.Contains("Suspicious email attachment"))
                .ToList();

            var bruteForceDetections = allDetections
                .Where(d => d.LogSource != null && d.LogSource.Contains("Brute Force Attack"))
                .ToList();

            var ddosDetections = allDetections
                .Where(d => d.LogSource != null && d.LogSource.Contains("DDoS Attack"))
                .ToList();

            var systemAttackDetections = allDetections
                .Where(d => d.LogSource != null && d.LogSource.Contains("System Attack"))
                .ToList();

            var mobileAppAttackDetections = allDetections
                .Where(d => d.LogSource != null && d.LogSource.Contains("Mobile App Attack"))
                .ToList();

            var webAppAttackDetections = allDetections
                .Where(d => d.LogSource != null && d.LogSource.Contains("Web App Attack"))
                .ToList();

            var viewModel = new DashboardViewModel
            {
                TotalDetectionLogs = allDetections.Count,
                TotalNetworkLogs = totalNetworkLogs,
                RecentDetections = allDetections.OrderByDescending(d => d.Timestamp).Take(10).ToList(),
                DetectionsByType = allDetections.GroupBy(d => d.EventType ?? "Unknown").ToDictionary(g => g.Key, g => g.Count()),
                DetectionsBySeverity = allDetections.GroupBy(d => d.Severty ?? "Unknown").ToDictionary(g => g.Key, g => g.Count()),
                MalwareDetections = malwareDetections,
                PhishingDetections = phishingDetections,
                SuspiciousEmailDetections = suspiciousEmailDetections,
                BruteForceDetections = bruteForceDetections,
                DdosDetections = ddosDetections,
                SystemAttackDetections = systemAttackDetections,
                MobileAppAttackDetections = mobileAppAttackDetections,
                WebAppAttackDetections = webAppAttackDetections
            };

            return View(viewModel);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
