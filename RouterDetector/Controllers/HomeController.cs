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
            // Get filter parameters
            DateTime? startDate = Request.Query.ContainsKey("startDate") ? DateTime.Parse(Request.Query["startDate"]) : DateTime.Now.AddMonths(-6);
            DateTime? endDate = Request.Query.ContainsKey("endDate") ? DateTime.Parse(Request.Query["endDate"]) : DateTime.Now;
            var selectedEventType = Request.Query.ContainsKey("eventType") ? Request.Query["eventType"].ToString() : null;
            var selectedSeverity = Request.Query.ContainsKey("severity") ? Request.Query["severity"].ToString() : null;
            var selectedRuleType = Request.Query.ContainsKey("ruleType") ? Request.Query["ruleType"].ToString() : null;
            var selectedActionTaken = Request.Query.ContainsKey("actionTaken") ? Request.Query["actionTaken"].ToString() : null;

            // Build query with filters
            var query = _context.EventLogs.AsQueryable();
            
            if (startDate.HasValue)
                query = query.Where(e => e.Timestamp >= startDate.Value);
            
            if (endDate.HasValue)
                query = query.Where(e => e.Timestamp <= endDate.Value);
            
            if (!string.IsNullOrEmpty(selectedEventType))
                query = query.Where(e => e.EventType == selectedEventType);
            
            if (!string.IsNullOrEmpty(selectedSeverity))
                query = query.Where(e => e.Severity == selectedSeverity);
            
            if (!string.IsNullOrEmpty(selectedRuleType))
                query = query.Where(e => e.RuleType == selectedRuleType);
            
            if (!string.IsNullOrEmpty(selectedActionTaken))
                query = query.Where(e => e.ActionTaken == selectedActionTaken);

            var allEvents = await query.ToListAsync();

            // Basic threat categorization
            var malwareEvents = allEvents.Where(e => e.EventType != null && (
                    e.EventType.Contains("Malware", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Virus", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Worm", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Trojan", StringComparison.OrdinalIgnoreCase) ||
                    e.EventType.Contains("Intrusion", StringComparison.OrdinalIgnoreCase) ||
                e.EventType.Contains("MITM", StringComparison.OrdinalIgnoreCase))).ToList();

            var phishingEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Phishing", StringComparison.OrdinalIgnoreCase)).ToList();
            
            var suspiciousEmailEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Suspicious Email", StringComparison.OrdinalIgnoreCase)).ToList();

            var bruteForceEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Login Attempt", StringComparison.OrdinalIgnoreCase)).ToList();
            
            var ddosEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && 
                e.Message != null && e.Message.Contains("DDoS", StringComparison.OrdinalIgnoreCase)).ToList();
            
            var portScanEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Port Scan", StringComparison.OrdinalIgnoreCase)).ToList();
            
            var webAppAttackEvents = allEvents.Where(e => e.EventType != null && 
                e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && 
                e.Message != null && e.Message.Contains("Web application attack", StringComparison.OrdinalIgnoreCase)).ToList();

            // Analytics calculations
            var eventsByType = allEvents.GroupBy(e => e.EventType ?? "Unknown")
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsBySeverity = allEvents.GroupBy(e => e.Severity ?? "Unknown")
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsByRuleType = allEvents.GroupBy(e => e.RuleType ?? "Unknown")
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsByActionTaken = allEvents.GroupBy(e => e.ActionTaken ?? "Unknown")
                .ToDictionary(g => g.Key, g => g.Count());

            // Time-based analytics
            var eventsByMonth = allEvents.GroupBy(e => e.Timestamp.ToString("yyyy-MM"))
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsByYear = allEvents.GroupBy(e => e.Timestamp.Year.ToString())
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsByDay = allEvents.GroupBy(e => e.Timestamp.ToString("yyyy-MM-dd"))
                .OrderByDescending(g => g.Key)
                .Take(30)
                .ToDictionary(g => g.Key, g => g.Count());
            
            var eventsByHour = allEvents.GroupBy(e => e.Timestamp.Hour.ToString("00"))
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());

            // Source/Destination analytics
            var topSourceIPs = allEvents.Where(e => !string.IsNullOrEmpty(e.SrcIp))
                .GroupBy(e => e.SrcIp)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key!, g => g.Count());
            
            var topDestinationIPs = allEvents.Where(e => !string.IsNullOrEmpty(e.DstIp))
                .GroupBy(e => e.DstIp)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key!, g => g.Count());
            
            var topPorts = allEvents.Where(e => e.DstPort.HasValue)
                .GroupBy(e => e.DstPort.ToString())
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());

            // Attack type counts
            var attackTypeCounts = new Dictionary<string, int>
            {
                { "Port Scan", portScanEvents.Count },
                { "Brute Force", bruteForceEvents.Count },
                { "DDoS", ddosEvents.Count },
                { "Phishing", phishingEvents.Count },
                { "Web App Attack", webAppAttackEvents.Count },
                { "Malware", malwareEvents.Count },
                { "Suspicious Email", suspiciousEmailEvents.Count }
            };

            // Monthly trends
            var monthlyTrends = allEvents.GroupBy(e => e.Timestamp.ToString("yyyy-MM"))
                .OrderBy(g => g.Key)
                .Select(g => new MonthlyTrend
                {
                    Month = g.Key,
                    TotalEvents = g.Count(),
                    MalwareEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Malware", StringComparison.OrdinalIgnoreCase)),
                    PhishingEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Phishing", StringComparison.OrdinalIgnoreCase)),
                    BruteForceEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Login Attempt", StringComparison.OrdinalIgnoreCase)),
                    DdosEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("DDoS", StringComparison.OrdinalIgnoreCase)),
                    PortScanEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Port Scan", StringComparison.OrdinalIgnoreCase)),
                    WebAppAttackEvents = g.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("Web application attack", StringComparison.OrdinalIgnoreCase))
                }).ToList();

            var viewModel = new DashboardViewModel
            {
                // General Stats
                TotalEventLogs = allEvents.Count,
                TotalThreats = allEvents.Count(e => e.Severity == "High" || e.Severity == "Critical"),
                TotalBlocked = allEvents.Count(e => e.ActionTaken == "Blocked"),
                TotalQuarantined = allEvents.Count(e => e.ActionTaken == "Quarantined"),

                // Analytics
                RecentEvents = allEvents.OrderByDescending(e => e.Timestamp).Take(10).ToList(),
                EventsByType = eventsByType,
                EventsBySeverity = eventsBySeverity,
                EventsByRuleType = eventsByRuleType,
                EventsByActionTaken = eventsByActionTaken,

                // Time-based Analytics
                EventsByMonth = eventsByMonth,
                EventsByYear = eventsByYear,
                EventsByDay = eventsByDay,
                EventsByHour = eventsByHour,

                // Attack Analytics
                AttackTypeCounts = attackTypeCounts,
                TopSourceIPs = topSourceIPs,
                TopDestinationIPs = topDestinationIPs,
                TopPorts = topPorts,

                // Specific Threat Lists
                MalwareEvents = malwareEvents,
                PhishingEvents = phishingEvents,
                SuspiciousEmailEvents = suspiciousEmailEvents,
                BruteForceDetections = bruteForceEvents,
                DdosDetections = ddosEvents,
                PortScanDetections = portScanEvents,
                WebAppAttackDetections = webAppAttackEvents,

                // Trends
                MonthlyTrends = monthlyTrends,

                // Filter Options
                StartDate = startDate,
                EndDate = endDate,
                SelectedEventType = selectedEventType,
                SelectedSeverity = selectedSeverity,
                SelectedRuleType = selectedRuleType,
                SelectedActionTaken = selectedActionTaken
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> GetAnalyticsData()
        {
            var allEvents = await _context.EventLogs.ToListAsync();

            var analyticsData = new
            {
                eventsByType = allEvents.GroupBy(e => e.EventType ?? "Unknown")
                    .ToDictionary(g => g.Key, g => g.Count()),
                eventsBySeverity = allEvents.GroupBy(e => e.Severity ?? "Unknown")
                    .ToDictionary(g => g.Key, g => g.Count()),
                eventsByMonth = allEvents.GroupBy(e => e.Timestamp.ToString("yyyy-MM"))
                    .OrderBy(g => g.Key)
                    .ToDictionary(g => g.Key, g => g.Count()),
                attackTypeCounts = new Dictionary<string, int>
                {
                    { "Port Scan", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Port Scan", StringComparison.OrdinalIgnoreCase)) },
                    { "Brute Force", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Login Attempt", StringComparison.OrdinalIgnoreCase)) },
                    { "DDoS", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("DDoS", StringComparison.OrdinalIgnoreCase)) },
                    { "Phishing", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Phishing", StringComparison.OrdinalIgnoreCase)) },
                    { "Web App Attack", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("Web application attack", StringComparison.OrdinalIgnoreCase)) },
                    { "Malware", allEvents.Count(e => e.EventType != null && e.EventType.Contains("Malware", StringComparison.OrdinalIgnoreCase)) }
                }
            };

            return Json(analyticsData);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
