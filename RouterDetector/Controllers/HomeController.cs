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
                    e.EventType.Contains("Malware detected") ||
                    e.EventType.Contains("Worm") ||
                    e.EventType.Contains("Trojan")))
                .ToList();

            var phishingEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("Phishing detected"))
                .ToList();
            
            var suspiciousEmailEvents = allEvents
                .Where(e => e.EventType != null && e.EventType.Contains("Suspicious email attachment"))
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
