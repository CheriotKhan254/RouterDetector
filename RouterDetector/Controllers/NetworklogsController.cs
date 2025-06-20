using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;
using Microsoft.AspNetCore.Authorization;

namespace RouterDetector.Controllers
{
    [Authorize]
    public class NetworklogsController : Controller
    {
        private readonly RouterDetectorContext _context;

        public NetworklogsController(RouterDetectorContext context)
        {
            _context = context;
        }


        // GET: Networklogs
        public async Task<IActionResult> Index(
            string? filterIpAddress,
            string? filterProtocol,
            DateTime? filterStartDate,
            DateTime? filterEndDate,
            int pageNumber = 1,
            int pageSize = 50)
        {
            var query = _context.Networklogs.AsQueryable();

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
                query = query.Where(l => l.LogOccurrence >= filterStartDate);
            }

            if (filterEndDate.HasValue)
            {
                query = query.Where(l => l.LogOccurrence <= filterEndDate);
            }

            // Get total count before pagination
            var totalRecords = await query.CountAsync();

            // Apply pagination
            var logs = await query
                .OrderByDescending(n => n.LogOccurrence ?? DateTime.MinValue)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var model = new NetworkLogsViewModel
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

        // In your NetworklogsController.cs
        [HttpGet]
        public async Task<IActionResult> CheckNewLogs(DateTime lastLogTime)
        {
            var hasNewLogs = await _context.Networklogs
                .AnyAsync(l => l.LogOccurrence > lastLogTime);

            return Json(new { hasNewLogs });
        }

        // GET: Networklogs/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var networklogs = await _context.Networklogs
                .FirstOrDefaultAsync(m => m.Id == id);
            if (networklogs == null)
            {
                return NotFound();
            }

            return View(networklogs);
        }
    }
}
