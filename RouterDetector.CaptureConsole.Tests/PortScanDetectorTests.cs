using Xunit;
using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.Tests
{
    public class PortScanDetectorTests
    {
        [Fact]
        public void DetectsPortScan_WhenThresholdExceeded_Inbound()
        {
            var detector = new PortScanDetector(portThreshold: 5, timeWindowSeconds: 60);
            var sourceIp = IPAddress.Parse("1.2.3.4");
            var destIp = IPAddress.Parse("192.168.1.100");

            DetectionResult? result = null;
            for (ushort port = 1000; port < 1005; port++)
            {
                var packet = new NetworkPacket
                {
                    SourceIp = sourceIp,
                    DestinationIp = destIp,
                    DestinationPort = port,
                    TransportProtocol = TransportProtocol.Tcp,
                    IsInbound = true
                };
                result = detector.Analyze(packet);
            }

            Assert.NotNull(result);
            Assert.Equal("Port Scan", result.ProtocolName);
            Assert.Equal(ThreatSeverity.High, result.Severity);
        }

        [Fact]
        public void DoesNotDetectPortScan_Outbound()
        {
            var detector = new PortScanDetector(portThreshold: 5, timeWindowSeconds: 60);
            var sourceIp = IPAddress.Parse("1.2.3.4");
            var destIp = IPAddress.Parse("192.168.1.100");

            DetectionResult? result = null;
            for (ushort port = 1000; port < 1010; port++)
            {
                var packet = new NetworkPacket
                {
                    SourceIp = sourceIp,
                    DestinationIp = destIp,
                    DestinationPort = port,
                    TransportProtocol = TransportProtocol.Tcp,
                    IsInbound = false,
                    IsOutbound = true
                };
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }

        [Fact]
        public void DoesNotDetectPortScan_IfThresholdNotReached()
        {
            var detector = new PortScanDetector(portThreshold: 5, timeWindowSeconds: 60);
            var sourceIp = IPAddress.Parse("1.2.3.4");
            var destIp = IPAddress.Parse("192.168.1.100");

            DetectionResult? result = null;
            for (ushort port = 1000; port < 1004; port++)
            {
                var packet = new NetworkPacket
                {
                    SourceIp = sourceIp,
                    DestinationIp = destIp,
                    DestinationPort = port,
                    TransportProtocol = TransportProtocol.Tcp,
                    IsInbound = true
                };
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }
    }
}