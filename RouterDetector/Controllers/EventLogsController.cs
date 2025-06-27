using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;
using System.Linq;

namespace RouterDetector.Controllers
{
    [Authorize]
    public class EventLogsController : Controller
    {
        private readonly RouterDetectorContext _context;

        public EventLogsController(RouterDetectorContext context)
        {
            _context = context;
        }

        // GET: EventLogs
        public async Task<IActionResult> Index(
            string? filterIpAddress,
            string? filterProtocol,
            DateTime? filterStartDate,
            DateTime? filterEndDate,
            int pageNumber = 1,
            int pageSize = 50)
        {
            var query = _context.EventLogs.AsQueryable();

            // Apply filters
            if (!string.IsNullOrEmpty(filterIpAddress))
            {
                query = query.Where(l => l.SrcIp.Contains(filterIpAddress) || l.DstIp.Contains(filterIpAddress));
            }

            if (!string.IsNullOrEmpty(filterProtocol))
            {
                query = query.Where(l => l.Protocol == filterProtocol);
            }

            if (filterStartDate.HasValue)
            {
                query = query.Where(l => l.Timestamp >= filterStartDate);
            }

            if (filterEndDate.HasValue)
            {
                query = query.Where(l => l.Timestamp <= filterEndDate);
            }

            // Get total count before pagination
            var totalRecords = await query.CountAsync();

            // Apply pagination
            var logs = await query
                .OrderByDescending(n => n.Timestamp)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Use a simple view model for now
            var model = new EventLogsViewModel
            {
                Logs = logs,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalRecords = totalRecords,
                FilterIpAddress = filterIpAddress,
                FilterProtocol = filterProtocol,
                FilterStartDate = filterStartDate,
                FilterEndDate = filterEndDate
            };

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> CheckNewLogs(DateTime lastLogTime)
        {
            var hasNewLogs = await _context.EventLogs
                .AnyAsync(l => l.Timestamp > lastLogTime);

            return Json(new { hasNewLogs });
        }

        // GET: EventLogs/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var eventLog = await _context.EventLogs
                .FirstOrDefaultAsync(m => m.Id == id);
            if (eventLog == null)
            {
                return NotFound();
            }

            return View(eventLog);
        }
    }

    // Simple view model for the index view
    public class EventLogsViewModel
    {
        public List<EventLog> Logs { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public string FilterIpAddress { get; set; }
        public string FilterProtocol { get; set; }
        public DateTime? FilterStartDate { get; set; }
        public DateTime? FilterEndDate { get; set; }
    }
} 