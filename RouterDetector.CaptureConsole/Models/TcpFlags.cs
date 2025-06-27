namespace RouterDetector.CaptureConsole.Models
{
    [Flags]
    public enum TcpFlags : ushort
    {
        None = 0,
        Fin = 0x01, // Updated to use the correct flag value directly
        Syn = 0x02,
        Rst = 0x04,
        Psh = 0x08,
        Ack = 0x10,
        Urg = 0x20,
        Ece = 0x40,
        Cwr = 0x80
    }

}
