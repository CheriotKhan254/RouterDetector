using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using RouterDetector.Data;
using RouterDetector.Models;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace RouterDetector.Controllers
{
    [Authorize]
    public class AnalyticsController : Controller
    {
        private readonly RouterDetectorContext _context;
        private readonly ILogger<AnalyticsController> _logger;

        public AnalyticsController(RouterDetectorContext context, ILogger<AnalyticsController> logger)
        {
            _context = context;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return RedirectToAction("Dashboard", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> GetRealTimeData()
        {
            try
            {
                var last24Hours = DateTime.Now.AddHours(-24);
                var recentEvents = await _context.EventLogs
                    .Where(e => e.Timestamp >= last24Hours)
                    .ToListAsync();

                var realTimeData = new
                {
                    totalEvents = recentEvents.Count,
                    eventsByHour = recentEvents.GroupBy(e => e.Timestamp.Hour)
                        .OrderBy(g => g.Key)
                        .ToDictionary(g => g.Key.ToString("00"), g => g.Count()),
                    topAttackTypes = recentEvents.GroupBy(e => e.EventType ?? "Unknown")
                        .OrderByDescending(g => g.Count())
                        .Take(5)
                        .ToDictionary(g => g.Key, g => g.Count()),
                    severityDistribution = recentEvents.GroupBy(e => e.Severity ?? "Unknown")
                        .ToDictionary(g => g.Key, g => g.Count()),
                    lastUpdate = DateTime.Now
                };

                return Json(realTimeData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting real-time analytics data");
                return StatusCode(500, new { error = "Failed to retrieve analytics data" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAttackTrends([FromQuery] DateTime? startDate, [FromQuery] DateTime? endDate)
        {
            try
            {
                var query = _context.EventLogs.AsQueryable();
                
                if (startDate.HasValue)
                    query = query.Where(e => e.Timestamp >= startDate.Value);
                
                if (endDate.HasValue)
                    query = query.Where(e => e.Timestamp <= endDate.Value);

                var events = await query.ToListAsync();

                var trends = events.GroupBy(e => e.Timestamp.ToString("yyyy-MM-dd"))
                    .OrderBy(g => g.Key)
                    .Select(g => new
                    {
                        date = g.Key,
                        totalEvents = g.Count(),
                        portScan = g.Count(e => e.EventType != null && e.EventType.Contains("Port Scan", StringComparison.OrdinalIgnoreCase)),
                        bruteForce = g.Count(e => e.EventType != null && e.EventType.Contains("Login Attempt", StringComparison.OrdinalIgnoreCase)),
                        ddos = g.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("DDoS", StringComparison.OrdinalIgnoreCase)),
                        phishing = g.Count(e => e.EventType != null && e.EventType.Contains("Phishing", StringComparison.OrdinalIgnoreCase)),
                        webAppAttack = g.Count(e => e.EventType != null && e.EventType.Contains("Policy Violation", StringComparison.OrdinalIgnoreCase) && e.Message != null && e.Message.Contains("Web application attack", StringComparison.OrdinalIgnoreCase))
                    })
                    .ToList();

                return Json(trends);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting attack trends");
                return StatusCode(500, new { error = "Failed to retrieve attack trends" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetTopThreats([FromQuery] int limit = 10)
        {
            try
            {
                var topThreats = await _context.EventLogs
                    .Where(e => e.Severity == "High" || e.Severity == "Critical")
                    .GroupBy(e => new { e.EventType, e.SrcIp, e.Severity })
                    .OrderByDescending(g => g.Count())
                    .Take(limit)
                    .Select(g => new
                    {
                        eventType = g.Key.EventType,
                        sourceIp = g.Key.SrcIp,
                        severity = g.Key.Severity,
                        count = g.Count(),
                        lastOccurrence = g.Max(e => e.Timestamp)
                    })
                    .ToListAsync();

                return Json(topThreats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting top threats");
                return StatusCode(500, new { error = "Failed to retrieve top threats" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetGeographicData()
        {
            try
            {
                var sourceIPs = await _context.EventLogs
                    .Where(e => !string.IsNullOrEmpty(e.SrcIp))
                    .GroupBy(e => e.SrcIp)
                    .OrderByDescending(g => g.Count())
                    .Take(20)
                    .Select(g => new
                    {
                        ip = g.Key,
                        count = g.Count(),
                        country = "Unknown", // You can integrate with IP geolocation service
                        city = "Unknown"
                    })
                    .ToListAsync();

                return Json(sourceIPs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting geographic data");
                return StatusCode(500, new { error = "Failed to retrieve geographic data" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> ExportReport([FromQuery] DateTime? startDate, [FromQuery] DateTime? endDate, [FromQuery] string format = "json")
        {
            try
            {
                var query = _context.EventLogs.AsQueryable();
                
                if (startDate.HasValue)
                    query = query.Where(e => e.Timestamp >= startDate.Value);
                
                if (endDate.HasValue)
                    query = query.Where(e => e.Timestamp <= endDate.Value);

                var events = await query.OrderByDescending(e => e.Timestamp).ToListAsync();

                if (format.ToLower() == "csv")
                {
                    var csv = "Timestamp,EventType,RuleType,SourceIP,DestinationIP,Severity,ActionTaken,Message,Notes\n";
                    csv += string.Join("\n", events.Select(e => 
                        $"\"{e.Timestamp}\",\"{e.EventType}\",\"{e.RuleType}\",\"{e.SrcIp}\",\"{e.DstIp}\",\"{e.Severity}\",\"{e.ActionTaken}\",\"{e.Message}\",\"{e.Notes}\""));
                    
                    return File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", $"security_report_{DateTime.Now:yyyyMMdd}.csv");
                }
                else
                {
                    var report = new
                    {
                        generatedAt = DateTime.Now,
                        period = new { start = startDate, end = endDate },
                        summary = new
                        {
                            totalEvents = events.Count,
                            highSeverity = events.Count(e => e.Severity == "High"),
                            criticalSeverity = events.Count(e => e.Severity == "Critical"),
                            blocked = events.Count(e => e.ActionTaken == "Blocked"),
                            quarantined = events.Count(e => e.ActionTaken == "Quarantined")
                        },
                        events = events.Select(e => new
                        {
                            e.Timestamp,
                            e.EventType,
                            e.RuleType,
                            e.SrcIp,
                            e.DstIp,
                            e.Severity,
                            e.ActionTaken,
                            e.Message,
                            e.Notes
                        })
                    };

                    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
                    return File(System.Text.Encoding.UTF8.GetBytes(json), "application/json", $"security_report_{DateTime.Now:yyyyMMdd}.json");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting report");
                return StatusCode(500, new { error = "Failed to export report" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetPerformanceMetrics()
        {
            try
            {
                var last30Days = DateTime.Now.AddDays(-30);
                var events = await _context.EventLogs
                    .Where(e => e.Timestamp >= last30Days)
                    .ToListAsync();

                var metrics = new
                {
                    averageEventsPerDay = events.Count / 30.0,
                    peakHour = events.GroupBy(e => e.Timestamp.Hour)
                        .OrderByDescending(g => g.Count())
                        .First().Key,
                    mostCommonAttackType = events.GroupBy(e => e.EventType)
                        .OrderByDescending(g => g.Count())
                        .First().Key,
                    detectionRate = events.Count(e => e.ActionTaken == "Blocked" || e.ActionTaken == "Quarantined") / (double)events.Count * 100,
                    falsePositiveRate = events.Count(e => e.Severity == "Low") / (double)events.Count * 100
                };

                return Json(metrics);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting performance metrics");
                return StatusCode(500, new { error = "Failed to retrieve performance metrics" });
            }
        }
    }
} 