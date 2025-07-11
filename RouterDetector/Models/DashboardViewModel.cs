using System.Collections.Generic;

namespace RouterDetector.Models
{
    public class DashboardViewModel
    {
        // General Stats
        public int TotalEventLogs { get; set; }
        public int TotalThreats { get; set; }
        public int TotalBlocked { get; set; }
        public int TotalQuarantined { get; set; }

        // Threat Analytics
        public List<EventLog> RecentEvents { get; set; } = new();
        public Dictionary<string, int> EventsByType { get; set; } = new();
        public Dictionary<string, int> EventsBySeverity { get; set; } = new();
        public Dictionary<string, int> EventsByRuleType { get; set; } = new();
        public Dictionary<string, int> EventsByActionTaken { get; set; } = new();

        // Time-based Analytics
        public Dictionary<string, int> EventsByMonth { get; set; } = new();
        public Dictionary<string, int> EventsByYear { get; set; } = new();
        public Dictionary<string, int> EventsByDay { get; set; } = new();
        public Dictionary<string, int> EventsByHour { get; set; } = new();

        // Attack Type Analytics
        public Dictionary<string, int> AttackTypeCounts { get; set; } = new();
        public Dictionary<string, int> AttackTypeByMonth { get; set; } = new();
        public Dictionary<string, int> AttackTypeBySeverity { get; set; } = new();

        // Source/Destination Analytics
        public Dictionary<string, int> TopSourceIPs { get; set; } = new();
        public Dictionary<string, int> TopDestinationIPs { get; set; } = new();
        public Dictionary<string, int> TopPorts { get; set; } = new();

        // Specific Threat Lists
        public List<EventLog> MalwareDetections { get; set; } = new();
        public List<EventLog> PhishingDetections { get; set; } = new();
        public List<EventLog> SuspiciousEmailDetections { get; set; } = new();
        public List<EventLog> BruteForceDetections { get; set; } = new();
        public List<EventLog> DdosDetections { get; set; } = new();
        public List<EventLog> SystemAttackDetections { get; set; } = new();
        public List<EventLog> MobileAppAttackDetections { get; set; } = new();
        public List<EventLog> WebAppAttackDetections { get; set; } = new();
        public List<EventLog> PortScanDetections { get; set; } = new();
        public List<EventLog> MalwareEvents { get; set; } = new();
        public List<EventLog> PhishingEvents { get; set; } = new();
        public List<EventLog> SuspiciousEmailEvents { get; set; } = new();

        // Trend Analysis
        public List<MonthlyTrend> MonthlyTrends { get; set; } = new();
        public List<AttackTrend> AttackTrends { get; set; } = new();
        public List<SeverityTrend> SeverityTrends { get; set; } = new();

        // Filter Options
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public string? SelectedEventType { get; set; }
        public string? SelectedSeverity { get; set; }
        public string? SelectedRuleType { get; set; }
        public string? SelectedActionTaken { get; set; }
    }

    public class MonthlyTrend
    {
        public string Month { get; set; } = string.Empty;
        public int TotalEvents { get; set; }
        public int MalwareEvents { get; set; }
        public int PhishingEvents { get; set; }
        public int BruteForceEvents { get; set; }
        public int DdosEvents { get; set; }
        public int PortScanEvents { get; set; }
        public int WebAppAttackEvents { get; set; }
    }

    public class AttackTrend
    {
        public string AttackType { get; set; } = string.Empty;
        public int Count { get; set; }
        public string Severity { get; set; } = string.Empty;
        public DateTime Date { get; set; }
    }

    public class SeverityTrend
    {
        public string Severity { get; set; } = string.Empty;
        public int Count { get; set; }
        public DateTime Date { get; set; }
    }
} 