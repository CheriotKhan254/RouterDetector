using System;
using Microsoft.Extensions.Configuration;
using PacketDotNet;
using SharpPcap;
using RouterDetector.Models;
using RouterDetector.Data;
using Microsoft.EntityFrameworkCore;

namespace RouterDetector.CaptureConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            // TCP flag bitmasks
            const ushort TCP_FLAG_RST = 0x04;
            const ushort TCP_FLAG_SYN = 0x02;
            const ushort TCP_FLAG_ACK = 0x10;

            // Load configuration
            var config = new ConfigurationBuilder()
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddJsonFile("appsettings.json")
                .Build();
            var optionsBuilder = new DbContextOptionsBuilder<RouterDetectorContext>();
            optionsBuilder.UseSqlServer(config.GetConnectionString("Default-Connection"));

            while (true)
            {
                // List network devices
                var devices = CaptureDeviceList.Instance;
                if (devices.Count == 0)
                {
                    Console.WriteLine("No devices found.");
                    return;
                }
                Console.WriteLine("Available devices:");
                for (int i = 0; i < devices.Count; i++)
                {
                    Console.WriteLine($"{i}: {devices[i].Description}");
                }
                Console.Write("Select device: ");
                int deviceIndex = int.Parse(Console.ReadLine());
                var device = devices[deviceIndex];

                // Open device
                device.OnPacketArrival += (sender, e) =>
                {
                    try
                    {
                        var rawPacket = e.GetPacket();
                        var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                        var ipPacket = packet.Extract<PacketDotNet.IPPacket>();
                        var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();

                        if (ipPacket != null && tcpPacket != null)
                        {
                            // Suspicious: TCP RST
                            if ((tcpPacket.Flags & TCP_FLAG_RST) != 0)
                            {
                                SaveDetection(ipPacket, tcpPacket, "TCP RST Detected", "Medium", optionsBuilder.Options);
                            }
                            // Suspicious: Telnet traffic
                            if (tcpPacket.DestinationPort == 23 || tcpPacket.SourcePort == 23)
                            {
                                SaveDetection(ipPacket, tcpPacket, "Telnet Traffic Detected", "High", optionsBuilder.Options);
                            }
                            // Suspicious: SYN scan (SYN without ACK)
                            if ((tcpPacket.Flags & TCP_FLAG_SYN) != 0 && (tcpPacket.Flags & TCP_FLAG_ACK) == 0)
                            {
                                SaveDetection(ipPacket, tcpPacket, "Possible SYN Scan", "High", optionsBuilder.Options);
                            }
                            // HTTP/HTTPS Traffic
                            if (tcpPacket.DestinationPort == 80 || tcpPacket.SourcePort == 80)
                            {
                                SaveDetection(ipPacket, tcpPacket, "HTTP Traffic", "Low", optionsBuilder.Options);
                            }
                            if (tcpPacket.DestinationPort == 443 || tcpPacket.SourcePort == 443)
                            {
                                SaveDetection(ipPacket, tcpPacket, "HTTPS Traffic", "Low", optionsBuilder.Options);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error processing packet: " + ex.Message);
                    }
                };

                device.Open(); // Promiscuous mode by default
                Console.WriteLine("Capturing on " + device.Description + " (press Ctrl+C to stop)");
                device.StartCapture();
                Console.CancelKeyPress += (s, e) =>
                {
                    device.StopCapture();
                    device.Close();
                    Console.WriteLine("Capture stopped.");
                    e.Cancel = true; // Prevent application exit
                };

                // Wait for user to stop capture
                Console.WriteLine("Press Enter to select another device or Ctrl+C to exit.");
                Console.ReadLine();
            }
        }

        static void SaveDetection(IPPacket ip, TcpPacket tcp, string eventType, string severity, DbContextOptions<RouterDetectorContext> options)
        {
            using var db = new RouterDetectorContext(options);
            var now = DateTime.Now;

            // Infer protocol
            string protocol = ip.Protocol.ToString();

            // Infer device type (basic example: check common ports)
            string deviceType = "Unknown";
            if (tcp.DestinationPort == 80 || tcp.SourcePort == 80 || tcp.DestinationPort == 443 || tcp.SourcePort == 443)
            {
                deviceType = "Web Server";
            }
            else if (tcp.DestinationPort == 23 || tcp.SourcePort == 23)
            {
                deviceType = "Telnet Device";
            }
            else if (tcp.DestinationPort == 22 || tcp.SourcePort == 22)
            {
                deviceType = "SSH Device";
            }
            else if (tcp.DestinationPort == 3389 || tcp.SourcePort == 3389)
            {
                deviceType = "RDP Device";
            }

            // Set institution (could be made configurable)
            string institution = "DefaultInstitution";

            // Save to Networklogs (for flagged packets)
            var netLog = new Networklogs
            {
                SrcIp = ip.SourceAddress.ToString(),
                DstIp = ip.DestinationAddress.ToString(),
                SrcPort = tcp.SourcePort,
                DstPort = tcp.DestinationPort,
                Protocol = protocol,
                RuleType = eventType,
                LivePcap = true,
                Message = $"{eventType} (Flags: {tcp.Flags})",
                LogOccurrence = now
            };
            db.Networklogs.Add(netLog);

            // Save to Detectionlogs
            var detLog = new Detectionlogs
            {
                Timestamp = now,
                Institution = institution,
                SourceIP = ip.SourceAddress.ToString(),
                DeviceType = deviceType,
                LogSource = "CaptureConsole",
                EventType = eventType,
                Severty = severity,
                ActionTaken = "Logged",
                Notes = $"Detected by real-time capture. SrcPort: {tcp.SourcePort}, DstPort: {tcp.DestinationPort}, Protocol: {protocol}, DeviceType: {deviceType}"
            };
            db.Detectionlogs.Add(detLog);

            db.SaveChanges();
            Console.WriteLine($"[!] {eventType} detected: {ip.SourceAddress} -> {ip.DestinationAddress} ({tcp.SourcePort} -> {tcp.DestinationPort})");
        }
    }
}
