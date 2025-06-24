using RouterDetector.CaptureConsole.Interfaces;
using RouterDetector.CaptureConsole.Models;

namespace RouterDetector.CaptureConsole.DetectionProtocols
{
    internal class TestProtocol : IDetector
    {
        public string ProtocolName => "TEST_PROTOCOL";

        // Simple interval-based testing
        private int _packetCounter = 0;
        private const int TestInterval = 50; // Generate test every 50 packets

        public DetectionResult? Analyze(NetworkPacket packet)
        {
            _packetCounter++;

            // Every N packets, generate a test threat
            if (_packetCounter % TestInterval == 0)
            {
                return new DetectionResult(
                    isThreat: true,
                    packet,
                    $"TEST THREAT: Periodic test ({_packetCounter})",
                    ThreatSeverity.Low
                );
            }

            return null; // No threat for other packets
        }
    }
}