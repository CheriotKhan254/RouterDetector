using System.Collections.Generic;

namespace RouterDetector.Models
{
    public class DashboardViewModel
    {
        // General Stats
        public int TotalEventLogs { get; set; }

        // Threat Analytics
        public List<EventLog> RecentEvents { get; set; } = new();
        public Dictionary<string, int> EventsByType { get; set; } = new();
        public Dictionary<string, int> EventsBySeverity { get; set; } = new();

        // Specific Threat Lists
        public List<EventLog> MalwareDetections { get; set; } = new();
        public List<EventLog> PhishingDetections { get; set; } = new();
        public List<EventLog> SuspiciousEmailDetections { get; set; } = new();
        public List<EventLog> BruteForceDetections { get; set; } = new();
        public List<EventLog> DdosDetections { get; set; } = new();
        public List<EventLog> SystemAttackDetections { get; set; } = new();
        public List<EventLog> MobileAppAttackDetections { get; set; } = new();
        public List<EventLog> WebAppAttackDetections { get; set; } = new();
        public List<EventLog> MalwareEvents { get; set; } = new();
        public List<EventLog> PhishingEvents { get; set; } = new();
        public List<EventLog> SuspiciousEmailEvents { get; set; } = new();
    }
} 