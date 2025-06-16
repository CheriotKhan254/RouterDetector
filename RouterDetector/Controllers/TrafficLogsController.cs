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
        public async Task<ActionResult<IEnumerable<Networklogs>>> GetNetworkLogs()
        {
            var logs = await _context.Networklogs
                .OrderByDescending(n => n.LogOccurrence)
                .Take(1000)
                .ToListAsync();
            return Ok(logs);
        }

        // GET: api/TrafficLogs/detections
        [HttpGet("detections")]
        public async Task<ActionResult<IEnumerable<Detectionlogs>>> GetDetectionLogs()
        {
            var logs = await _context.Detectionlogs
                .OrderByDescending(d => d.Timestamp)
                .Take(1000)
                .ToListAsync();
            return Ok(logs);
        }
    }
}
