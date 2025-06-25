using RouterDetector.Models;
using System.Collections.Generic;

namespace RouterDetector.Models
{
    public class DashboardViewModel
    {
        // General Stats
        public int TotalDetectionLogs { get; set; }
        public int TotalNetworkLogs { get; set; }

        // Threat Analytics
        public List<Detectionlogs> RecentDetections { get; set; } = new();
        public Dictionary<string, int> DetectionsByType { get; set; } = new();
        public Dictionary<string, int> DetectionsBySeverity { get; set; } = new();

        // Specific Threat Lists
        public List<Detectionlogs> MalwareDetections { get; set; } = new();
        public List<Detectionlogs> PhishingDetections { get; set; } = new();
        public List<Detectionlogs> SuspiciousEmailDetections { get; set; } = new();
    }
} 