using RouterDetector.CaptureConsole.Models;

namespace RouterDetector.CaptureConsole.Interfaces
{
    public interface IDetector
    {
        string ProtocolName { get; }

        DetectionResult? Analyze(NetworkPacket packet);


    }
}
