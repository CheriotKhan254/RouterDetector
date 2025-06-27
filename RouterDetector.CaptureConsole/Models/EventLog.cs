using System;
using System.ComponentModel.DataAnnotations;

namespace RouterDetector.CaptureConsole.Models
{
    public class EventLog
    {
        [Key]
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string Institution { get; set; }
        public string DeviceName { get; set; }
        public string DeviceType { get; set; }
        public string LogSource { get; set; }
        public string EventType { get; set; }
        public string Severity { get; set; }
        public string Username { get; set; }
        public string SrcIp { get; set; }
        public string DstIp { get; set; }
        public int? SrcPort { get; set; }
        public int? DstPort { get; set; }
        public string Protocol { get; set; }
        public string ActionTaken { get; set; }
        public string NatSrcIp { get; set; }
        public string NatDstIp { get; set; }
        public string Hostname { get; set; }
        public string Notes { get; set; }
        public string RuleType { get; set; }
        public string LivePcap { get; set; }
        public string Message { get; set; }
        public string LogOccurrence { get; set; }
        public string EventType2 { get; set; }
        public string Severity2 { get; set; }
        public string UserAccount { get; set; }
        public string ActionTaken2 { get; set; }
    }
} 