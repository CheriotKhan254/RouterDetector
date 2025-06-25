using System.Text.Json.Serialization;

namespace RouterDetector.CaptureConsole.Models
{

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ThreatSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public sealed record DetectionResult
    {
        public bool IsThreat { get; init; }
        public NetworkPacket OriginalPacket { get; init; }
        public string ThreatDescription { get; init; }
        public ThreatSeverity Severity { get; init; }
        public DateTime DetectionTime { get; init; } = DateTime.UtcNow;
        public string ProtocolName { get; init; }

        // Optional constructor for required fields
        public DetectionResult(bool isThreat, NetworkPacket packet,
                             string description, ThreatSeverity severity, string protocolName)
        {
            IsThreat = isThreat;
            OriginalPacket = packet;
            ThreatDescription = description;
            Severity = severity;
            ProtocolName = protocolName;
        }

        public string GetSummary() =>
            $"[{Severity}] {ThreatDescription} at {DetectionTime:u}";

        public override string ToString() =>
            $"Threat: {IsThreat} | {GetSummary()}";
    }
}
