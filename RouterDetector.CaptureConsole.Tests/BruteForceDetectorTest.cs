using Xunit;
using RouterDetector.CaptureConsole.DetectionProtocols;
using RouterDetector.CaptureConsole.Models;
using System.Net;

namespace RouterDetector.CaptureConsole.Tests
{
    public class BruteForceDetectorTests
    {
        private static IPAddress GetRandomIp()
        {
            var rand = new Random();
            var bytes = new byte[4];
            rand.NextBytes(bytes);
            // Avoid reserved ranges for realism
            if (bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 || bytes[0] >= 224) bytes[0] = 100;
            return new IPAddress(bytes);
        }

        [Fact]
        public void DetectsBruteForce_WhenThresholdExceeded_Inbound()
        {
            var config = new DetectionThresholds();
            var detector = new BruteForceDetector(config.BruteForcePortThresholds, config.BruteForceTimeWindowSeconds, config.BruteForceWhitelistedIPs);
            var randomIp = GetRandomIp();
            var packet = new NetworkPacket
            {
                SourceIp = randomIp,
                DestinationPort = 22, // SSH port (threshold = 5)
                IsInbound = true
            };

            DetectionResult? result = null;
            for (int i = 0; i < 5; i++)
            {
                result = detector.Analyze(packet);
            }

            Assert.NotNull(result);
            Assert.Equal("Brute Force Attack", result.ProtocolName);
        }

        [Fact]
        public void DoesNotDetectBruteForce_Outbound()
        {
            var config = new DetectionThresholds();
            var detector = new BruteForceDetector(config.BruteForcePortThresholds, config.BruteForceTimeWindowSeconds, config.BruteForceWhitelistedIPs);
            var randomIp = GetRandomIp();
            var packet = new NetworkPacket
            {
                SourceIp = randomIp,
                DestinationPort = 22,
                IsInbound = false,
                IsOutbound = true
            };

            DetectionResult? result = null;
            for (int i = 0; i < 10; i++)
            {
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }

        [Fact]
        public void DoesNotDetectBruteForce_Internal()
        {
            var config = new DetectionThresholds();
            var detector = new BruteForceDetector(config.BruteForcePortThresholds, config.BruteForceTimeWindowSeconds, config.BruteForceWhitelistedIPs);
            var randomIp = GetRandomIp();
            var packet = new NetworkPacket
            {
                SourceIp = randomIp,
                DestinationPort = 22,
                IsInbound = false,
                IsOutbound = false,
                IsInternal = true
            };

            DetectionResult? result = null;
            for (int i = 0; i < 10; i++)
            {
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }

        [Fact]
        public void DoesNotDetectBruteForce_IfThresholdNotReached()
        {
            var config = new DetectionThresholds();
            var detector = new BruteForceDetector(config.BruteForcePortThresholds, config.BruteForceTimeWindowSeconds, config.BruteForceWhitelistedIPs);
            var randomIp = GetRandomIp();
            var packet = new NetworkPacket
            {
                SourceIp = randomIp,
                DestinationPort = 22,
                IsInbound = true
            };

            DetectionResult? result = null;
            for (int i = 0; i < 4; i++) // threshold for port 22 is 5
            {
                result = detector.Analyze(packet);
            }

            Assert.Null(result);
        }

        [Fact]
        public void DetectsBruteForce_WithDifferentPorts_UsesCorrectThreshold()
        {
            var config = new DetectionThresholds();
            var detector = new BruteForceDetector(config.BruteForcePortThresholds, config.BruteForceTimeWindowSeconds, config.BruteForceWhitelistedIPs);
            var randomIp = GetRandomIp();
            var packet = new NetworkPacket
            {
                SourceIp = randomIp,
                DestinationPort = 80, // HTTP port (threshold = 50)
                IsInbound = true
            };

            DetectionResult? result = null;
            for (int i = 0; i < 50; i++)
            {
                result = detector.Analyze(packet);
            }

            Assert.NotNull(result);
            Assert.Equal("Brute Force Attack", result.ProtocolName);
        }
    }
}