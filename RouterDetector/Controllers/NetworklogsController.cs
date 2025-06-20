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

        // GET: Networklogs/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Networklogs/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,SrcIp,DstIp,SrcPort,DstPort,Protocol,RuleType,LivePcap,Message,LogOccurrence")] Networklogs networklogs)
        {
            if (ModelState.IsValid)
            {
                // Ensure LogOccurrence is set
                if (networklogs.LogOccurrence == null)
                {
                    networklogs.LogOccurrence = DateTime.Now;
                }

                // Add the new log
                _context.Add(networklogs);
                await _context.SaveChangesAsync();

                // Delete older logs, keeping only the latest 1000
                var excessLogs = await _context.Networklogs
                    .OrderByDescending(l => l.LogOccurrence ?? DateTime.MinValue)
                    .Skip(1000)
                    .ToListAsync();

                if (excessLogs.Any())
                {
                    _context.Networklogs.RemoveRange(excessLogs);
                    await _context.SaveChangesAsync();
                }

                return RedirectToAction(nameof(Index));
            }

            return View(networklogs);
        }

        // GET: Networklogs/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var networklogs = await _context.Networklogs.FindAsync(id);
            if (networklogs == null)
            {
                return NotFound();
            }
            return View(networklogs);
        }

        // POST: Networklogs/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,SrcIp,DstIp,SrcPort,DstPort,Protocol,RuleType,LivePcap,Message,LogOccurrence")] Networklogs networklogs)
        {
            if (id != networklogs.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(networklogs);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!NetworklogsExists(networklogs.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(networklogs);
        }

        // GET: Networklogs/Delete/5
        public async Task<IActionResult> Delete(int? id)
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

        // POST: Networklogs/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var networklogs = await _context.Networklogs.FindAsync(id);
            if (networklogs != null)
            {
                _context.Networklogs.Remove(networklogs);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool NetworklogsExists(int id)
        {
            return _context.Networklogs.Any(e => e.Id == id);
        }
    }
}
