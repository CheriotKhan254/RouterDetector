using System.Net;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    // Well-known ports for readability
    public static class WellKnownPorts
    {
        public const ushort Ssh = 22;
        public const ushort Ftp = 21;
        public const ushort Telnet = 23;
        public const ushort Rdp = 3389;
        public const ushort Smtp = 25;
        public const ushort Pop3 = 110;
        public const ushort Imap = 143;
        public const ushort SmtpSubmission = 587;
        public const ushort Imaps = 993;
        public const ushort Pop3s = 995;
        public const ushort Http = 80;
        public const ushort Https = 443;
        public const ushort Mysql = 3306;
        public const ushort Postgresql = 5432;
        public const ushort Ldap = 389;
        public const ushort Ldaps = 636;
    }

    public enum TrafficDirection
    {
        Inbound,
        Outbound,
        Both
    }

    // Thresholds and config for each protocol
    public class DetectionThresholds
    {
        // HTTPS Volume
        public int HttpsVolumeConnectionThreshold { get; set; } = 100;
        public int HttpsVolumeTimeWindowSeconds { get; set; } = 60;
        public TrafficDirection HttpsVolumeDirection { get; set; } = TrafficDirection.Inbound;
        public HashSet<string> HttpsVolumeWhitelistedDomains { get; set; } = new()
        {
            "google.com", "cloudflare.com", "microsoft.com", "facebook.com"
        };
        public HashSet<IPAddress> HttpsVolumeWhitelistedIPs { get; set; } = new()
        {
            IPAddress.Parse("8.8.8.8"), // Google DNS
            IPAddress.Parse("8.8.4.4"), // Google DNS
            IPAddress.Parse("1.1.1.1"), // Cloudflare
            IPAddress.Parse("1.0.0.1")  // Cloudflare
        };

        // DDoS
        public int DdosPacketThreshold { get; set; } = 100;
        public int DdosTimeWindowSeconds { get; set; } = 10;
        public int DdosSourceDiversityThreshold { get; set; } = 1; // Number of unique sources
        public HashSet<string> DdosAllowedProtocols { get; set; } = ["TCP", "UDP", "ICMP"];
        public HashSet<IPAddress> DdosWhitelistedIPs { get; set; } =
        [
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("1.1.1.1")
        ];

        // Port Scan
        public int PortScanPortThreshold { get; set; } = 5;
        public int PortScanTimeWindowSeconds { get; set; } = 60;
        public HashSet<IPAddress> PortScanWhitelistedIPs { get; set; } = new()
        {
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("1.1.1.1")
        };

        // Brute Force (per-port)
        public Dictionary<ushort, int> BruteForcePortThresholds { get; set; } = new()
        {
            { WellKnownPorts.Ssh, 5 },    // SSH: Lower threshold due to high sensitivity
            { WellKnownPorts.Ftp, 10 },   // FTP
            { WellKnownPorts.Telnet, 5 }, // Telnet: Lower due to legacy protocol
            { WellKnownPorts.Rdp, 10 },   // RDP
            { WellKnownPorts.Smtp, 15 },  // SMTP
            { WellKnownPorts.Pop3, 15 },  // POP3
            { WellKnownPorts.Imap, 15 },  // IMAP
            { WellKnownPorts.SmtpSubmission, 15 }, // SMTP Submission
            { WellKnownPorts.Imaps, 15 }, // IMAPS
            { WellKnownPorts.Pop3s, 15 }, // POP3S
            { WellKnownPorts.Http, 50 },  // HTTP: Higher threshold for web traffic
            { WellKnownPorts.Https, 50 }, // HTTPS: Higher threshold for web traffic
            { WellKnownPorts.Mysql, 10 }, // MySQL
            { WellKnownPorts.Postgresql, 10 }, // PostgreSQL
            { WellKnownPorts.Ldap, 10 },  // LDAP
            { WellKnownPorts.Ldaps, 10 }  // LDAPS
        };
        public int BruteForceTimeWindowSeconds { get; set; } = 60;
        public HashSet<IPAddress> BruteForceWhitelistedIPs { get; set; } = new()
        {
            IPAddress.Parse("8.8.8.8"),
            IPAddress.Parse("1.1.1.1")
        };
    }
}
