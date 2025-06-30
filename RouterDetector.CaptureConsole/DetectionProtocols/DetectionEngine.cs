using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    public class DetectionEngine
    {
        private readonly List<IDetector> _detectors = new();

        public DetectionEngine()
        {
            _detectors.Add(new PortScanDetector());
           // _detectors.Add(new TestProtocol());
            _detectors.Add(new SignatureBasedDetector());
            _detectors.Add(new PhishingDetector());
            _detectors.Add(new SuspiciousEmailDetector());
            // Register new advanced detectors
            _detectors.Add(new BruteForceDetector());
            _detectors.Add(new DdosDetector());
            _detectors.Add(new SystemAttackDetector());
            _detectors.Add(new MobileAppAttackDetector());
            _detectors.Add(new WebAppAttackDetector());
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
