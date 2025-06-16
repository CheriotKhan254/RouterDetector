using System.ComponentModel.DataAnnotations;

namespace RouterDetector.Models
{
    public class Networklogs
    {
        [Key]
        public int Id { get; set; }
        public string? SrcIp { get; set; }
        public string? DstIp { get; set; }
        public int SrcPort { get; set; }
        public int DstPort { get; set; }
        public string? Protocol { get; set; }
        public string? RuleType { get; set; }
        public bool? LivePcap { get; set; }
        public string? Message { get; set; }
        public DateTime? LogOccurrence { get; set; }
    }
}
