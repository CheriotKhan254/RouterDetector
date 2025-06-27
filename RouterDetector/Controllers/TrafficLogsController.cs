using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RouterDetector.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TrafficLogsController : ControllerBase
    {
        private readonly RouterDetectorContext _context;

        public TrafficLogsController(RouterDetectorContext context)
        {
            _context = context;
        }

        // GET: api/TrafficLogs/network
        [HttpGet("network")]
        public async Task<ActionResult<IEnumerable<EventLog>>> GetNetworkLogs()
        {
            // Optionally filter by event type or other criteria if needed
            var logs = await _context.EventLogs
                .OrderByDescending(n => n.Timestamp)
                .Take(1000)
                .ToListAsync();
            return Ok(logs);
        }

        // GET: api/TrafficLogs/detections
        [HttpGet("detections")]
        public async Task<ActionResult<IEnumerable<EventLog>>> GetDetectionLogs()
        {
            // Optionally filter by event type or other criteria if needed
            var logs = await _context.EventLogs
                .OrderByDescending(e => e.Timestamp)
                .Take(1000)
                .ToListAsync();
            return Ok(logs);
        }
    }
}
