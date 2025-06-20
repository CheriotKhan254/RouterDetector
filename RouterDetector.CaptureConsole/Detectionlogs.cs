using System.ComponentModel.DataAnnotations;

namespace RouterDetector.Models
{
    public class Detectionlogs
    {
        [Key]
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string? Institution { get; set; }
        public string? SourceIP { get; set; }
        public string? DeviceType { get; set; }
        public string? LogSource { get; set; }
        public string? EventType { get; set; }
        public string? Severty { get; set; }
        public string? ActionTaken { get; set; }
        public string? Notes { get; set; }
    }
} 