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
            _detectors.Add(new TestProtocol());

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
