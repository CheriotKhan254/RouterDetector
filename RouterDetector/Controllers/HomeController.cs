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
            var allEvents = await _context.EventLogs.ToListAsync();

            var malwareEvents = allEvents
                .Where(e => e.EventType != null && (
                    e.EventType.Contains("Malware", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Virus", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Worm", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Trojan", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Intrusion", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("MITM", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            var phishingEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[Phishing]", StringComparison.OrdinalIgnoreCase))
                .ToList();
            
            var suspiciousEmailEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[Suspicious Email]", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var bruteForceEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[Brute Force]", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var ddosEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[DDoS]", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var systemAttackEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("System Attack", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var mobileAppAttackEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("Mobile App Attack", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var webAppAttackEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("Web App Attack", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var suspiciousPortScanEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[Suspicious Attack]", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var suspiciousHttpsEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("[Suspicious Activity]", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var viewModel = new DashboardViewModel
            {
                TotalEventLogs = allEvents.Count,
                RecentEvents = allEvents.OrderByDescending(e => e.Timestamp).Take(10).ToList(),
                EventsByType = allEvents.GroupBy(e => e.EventType ?? "Unknown").ToDictionary(g => g.Key, g => g.Count()),
                EventsBySeverity = allEvents.GroupBy(e => e.Severity ?? "Unknown").ToDictionary(g => g.Key, g => g.Count()),
                MalwareEvents = malwareEvents,
                PhishingEvents = phishingEvents,
                SuspiciousEmailEvents = suspiciousEmailEvents,
                BruteForceDetections = bruteForceEvents,
                DdosDetections = ddosEvents,
                SystemAttackDetections = systemAttackEvents,
                MobileAppAttackDetections = mobileAppAttackEvents,
                WebAppAttackDetections = webAppAttackEvents,
                // Optionally, you can add these to the view model if you want to display them separately:
                // SuspiciousPortScanEvents = suspiciousPortScanEvents,
                // SuspiciousHttpsEvents = suspiciousHttpsEvents,
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
