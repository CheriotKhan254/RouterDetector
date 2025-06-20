using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;
using Microsoft.AspNetCore.Authorization;

namespace RouterDetector.Controllers
{
    [Authorize]
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
    }
}
