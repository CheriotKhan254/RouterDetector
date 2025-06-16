using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Models;

namespace RouterDetector.Data
{
    public class RouterDetectorContext : DbContext
    {
        public RouterDetectorContext (DbContextOptions<RouterDetectorContext> options)
            : base(options)
        {
        }

        public DbSet<RouterDetector.Models.Detectionlogs> Detectionlogs { get; set; } = default!;
        public DbSet<RouterDetector.Models.Networklogs> Networklogs { get; set; } = default!;
    }
}
