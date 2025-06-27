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
        public List<EventLog> MalwareEvents { get; set; } = new();
        public List<EventLog> PhishingEvents { get; set; } = new();
        public List<EventLog> SuspiciousEmailEvents { get; set; } = new();
    }
} 