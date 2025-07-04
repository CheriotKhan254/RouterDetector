using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.Tests
{
    public class DDosDetectorTest
    {
        private DdosDetector CreateDetector() =>
            new DdosDetector(100, 10, 1, new HashSet<string> { "Tcp", "Udp" }, new HashSet<IPAddress>());

        [Fact]
        public void DetectsDdos_WhenThresholdReached()
        {
            var detector = CreateDetector();
            var destIp = IPAddress.Parse("192.168.1.100");

            DetectionResult? result = null;
            for (int i = 0; i < 100; i++) // default threshold
            {
                var packet = new NetworkPacket
                {
                    SourceIp = IPAddress.Parse($"10.0.0.{i}"),
                    DestinationIp = destIp,
                    IsInbound = true,
                    TransportProtocol = TransportProtocol.Tcp
                };
                result = detector.Analyze(packet);
            }

            Assert.NotNull(result);
            Assert.Equal("DDoS Attack", result.ProtocolName);
            Assert.Equal(ThreatSeverity.Critical, result.Severity);
        }

        [Fact]
        public void DoesNotDetectDdos_IfThresholdNotReached()
        {
            var detector = CreateDetector();
            var destIp = IPAddress.Parse("192.168.1.100");

            DetectionResult? result = null;
            for (int i = 0; i < 99; i++) // one less than threshold
            {
                var packet = new NetworkPacket
                {
                    SourceIp = IPAddress.Parse($"10.0.0.{i}"),
                    DestinationIp = destIp,
                    IsInbound = true,
                    TransportProtocol = TransportProtocol.Tcp
                };
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }
        [Fact]
        public void DoesNotDetectDdos_ForDifferentDestinations()
        {
            var detector = CreateDetector();

            DetectionResult? result = null;
            // 50 packets to each of two different IPs (never reaches threshold for either)
            for (int i = 0; i < 50; i++)
            {
                var packet1 = new NetworkPacket
                {
                    SourceIp = IPAddress.Parse($"10.0.0.{i}"),
                    DestinationIp = IPAddress.Parse("192.168.1.100"),
                    IsInbound = true,
                    TransportProtocol = TransportProtocol.Tcp
                };
                var packet2 = new NetworkPacket
                {
                    SourceIp = IPAddress.Parse($"10.0.1.{i}"),
                    DestinationIp = IPAddress.Parse("192.168.1.101"),
                    IsInbound = true,
                    TransportProtocol = TransportProtocol.Tcp
                };
                result = detector.Analyze(packet1);
                Assert.Null(result);
                result = detector.Analyze(packet2);
                Assert.Null(result);
            }
        }
    }
}
