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

            // Register the validated detectors
            _detectors.Add(new HttpsVolumeDetector());
            _detectors.Add(new DdosDetector());
            _detectors.Add(new BruteForceDetector());
            _detectors.Add(new PhishingDetector(_threatIntelService));
        }

        public DetectionResult? AnalyzePacket(NetworkPacket packet)
        {
            foreach (var detector in _detectors)
            {
                var result = detector.Analyze(packet);
                if (result is { IsThreat: true })
                {
                    return result;
                }
            }
            return null;
        }

        public void AddDetector(IDetector detector)
        {
            _detectors.Add(detector);
        }
    }
}
