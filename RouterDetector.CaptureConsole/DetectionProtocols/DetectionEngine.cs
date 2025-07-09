using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;
using RouterDetector.CaptureConsole.Services;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class DetectionEngine
    {
        private readonly List<IDetector> _detectors = new();
        private readonly ThreatIntelService _threatIntelService;

        public DetectionEngine()
        {
            _threatIntelService = new ThreatIntelService();
            var config = new DetectionThresholds();

            // Detects abnormal HTTPS traffic volume (possible data exfiltration or automated attacks)
            _detectors.Add(new HttpsVolumeDetector(
                config.HttpsVolumeConnectionThreshold,
                config.HttpsVolumeTimeWindowSeconds,
                config.HttpsVolumeDirection,
                config.HttpsVolumeWhitelistedIPs,
                config.HttpsVolumeWhitelistedDomains
            ));
            // Detects Distributed Denial of Service (DDoS) attacks (many sources, one target, high rate)
            _detectors.Add(new DdosDetector(
                config.DdosPacketThreshold,
                config.DdosTimeWindowSeconds,
                config.DdosSourceDiversityThreshold,
                config.DdosAllowedProtocols,
                config.DdosWhitelistedIPs
            ));
            // Detects brute force login attempts (repeated logins to auth ports from one IP)
            _detectors.Add(new BruteForceDetector(
                config.BruteForcePortThresholds,
                config.BruteForceTimeWindowSeconds,
                config.BruteForceWhitelistedIPs
            ));
            // Detects phishing attempts (packets containing blacklisted/suspicious links)
            _detectors.Add(new PhishingDetector(_threatIntelService));
            // Detects port scanning activity (one source IP accessing many ports quickly)
            _detectors.Add(new PortScanDetector(
                config.PortScanPortThreshold,
                config.PortScanTimeWindowSeconds,
                config.PortScanWhitelistedIPs
            ));
        }

        public List<DetectionResult> AnalyzePacket(NetworkPacket packet)
        {
            var results = new List<DetectionResult>();
            foreach (var detector in _detectors)
            {
                var result = detector.Analyze(packet);
                if (result is { IsThreat: true })
                {
                    results.Add(result);
                }
            }
            return results;
        }

        public void AddDetector(IDetector detector)
        {
            _detectors.Add(detector);
        }
    }
}
