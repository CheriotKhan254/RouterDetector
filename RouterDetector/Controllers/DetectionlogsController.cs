using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;

namespace RouterDetector.Controllers
{
    public class DetectionlogsController : Controller
    {
        private readonly RouterDetectorContext _context;

        public DetectionlogsController(RouterDetectorContext context)
        {
            _context = context;
        }

        // GET: Detectionlogs
        public async Task<IActionResult> Index()
        {
            return View(await _context.Detectionlogs.ToListAsync());
        }

        // GET: Detectionlogs/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var detectionlogs = await _context.Detectionlogs
                .FirstOrDefaultAsync(m => m.Id == id);
            if (detectionlogs == null)
            {
                return NotFound();
            }

            return View(detectionlogs);
        }

        // GET: Detectionlogs/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Detectionlogs/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Timestamp,Institution,SourceIP,DeviceType,LogSource,EventType,Severty,ActionTaken,Notes")] Detectionlogs detectionlogs)
        {
            if (ModelState.IsValid)
            {
                _context.Add(detectionlogs);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(detectionlogs);
        }

        // GET: Detectionlogs/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var detectionlogs = await _context.Detectionlogs.FindAsync(id);
            if (detectionlogs == null)
            {
                return NotFound();
            }
            return View(detectionlogs);
        }

        // POST: Detectionlogs/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Timestamp,Institution,SourceIP,DeviceType,LogSource,EventType,Severty,ActionTaken,Notes")] Detectionlogs detectionlogs)
        {
            if (id != detectionlogs.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(detectionlogs);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!DetectionlogsExists(detectionlogs.Id))
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
            return View(detectionlogs);
        }

        // GET: Detectionlogs/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var detectionlogs = await _context.Detectionlogs
                .FirstOrDefaultAsync(m => m.Id == id);
            if (detectionlogs == null)
            {
                return NotFound();
            }

            return View(detectionlogs);
        }

        // POST: Detectionlogs/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var detectionlogs = await _context.Detectionlogs.FindAsync(id);
            if (detectionlogs != null)
            {
                _context.Detectionlogs.Remove(detectionlogs);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool DetectionlogsExists(int id)
        {
            return _context.Detectionlogs.Any(e => e.Id == id);
        }
    }
}
