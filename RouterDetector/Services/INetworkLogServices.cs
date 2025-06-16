using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PacketDotNet;
using SharpPcap;
using RouterDetector.Data;
using RouterDetector.Models;

namespace RouterDetector.Services
{
    public class NetworkTrafficCaptureService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly string? _routerIp;

        public NetworkTrafficCaptureService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            _routerIp = GetDefaultGateway();
        }

        private string? GetDefaultGateway()
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up &&
                    (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                     nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                {
                    var gateway = nic.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (gateway != null)
                        return gateway.Address.ToString();
                }
            }
            return null;
        }

        private ICaptureDevice? GetNetworkCaptureDevice()
        {
            var devices = CaptureDeviceList.Instance;

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up &&
                    (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                     nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                {
                    var ipProps = nic.GetIPProperties();
                    var ip = ipProps.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;
                    if (ip != null)
                    {
                        var device = devices.FirstOrDefault(d => d.Description.Contains(nic.Description, StringComparison.OrdinalIgnoreCase));
                        if (device != null)
                            return device;
                    }
                }
            }
            return null;
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            return Task.Run(() =>
            {
                var device = GetNetworkCaptureDevice();

                if (device == null)
                {
                    Console.WriteLine("No suitable network device found for packet capture.");
                    return;
                }

                device.Open();
                device.OnPacketArrival += (sender, e) =>
                {
                    if (stoppingToken.IsCancellationRequested)
                    {
                        device.Close();
                        return;
                    }

                    var rawCapture = e.GetPacket();
                    var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                    var ipPacket = packet.Extract<IPPacket>();
                    var tcpPacket = packet.Extract<TcpPacket>();
                    var udpPacket = packet.Extract<UdpPacket>();

                    if (ipPacket != null)
                    {
                        if (string.IsNullOrEmpty(_routerIp) ||
                            (ipPacket.SourceAddress.ToString() != _routerIp && ipPacket.DestinationAddress.ToString() != _routerIp))
                            return;

                        string protocol = tcpPacket != null ? "TCP" : udpPacket != null ? "UDP" : ipPacket.Protocol.ToString();
                        int sourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
                        int destPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;

                        bool isMalicious = destPort == 22;

                        using (var scope = _serviceProvider.CreateScope())
                        {
                            var db = scope.ServiceProvider.GetRequiredService<RouterDetectorContext>();

                            var traffic = new Networklogs
                            {
                                SrcIp = ipPacket.SourceAddress.ToString(),
                                DstIp = ipPacket.DestinationAddress.ToString(),
                                SrcPort = sourcePort,
                                DstPort = destPort,
                                Protocol = protocol,
                                RuleType = isMalicious ? "Block" : "Allow",
                                LivePcap = true,
                                Message = isMalicious ? "Malicious SSH attempt detected" : "Normal traffic",
                                LogOccurrence = DateTime.Now
                            };

                            db.Networklogs.Add(traffic);
                            db.SaveChanges();

                            if (isMalicious)
                            {
                                var detection = new Detectionlogs
                                {
                                    Timestamp = DateTime.Now,
                                    Institution = "N/A",
                                    SourceIP = ipPacket.SourceAddress.ToString(),
                                    DeviceType = "Router",
                                    LogSource = "PCAP",
                                    EventType = "SSH Brute Force",
                                    Severty = "High", // matches your model spelling
                                    ActionTaken = "Blocked",
                                    Notes = "Detected by packet capture"
                                };

                                db.Detectionlogs.Add(detection);
                                db.SaveChanges();
                            }
                        }
                    }
                };

                device.StartCapture();

                while (!stoppingToken.IsCancellationRequested)
                {
                    Thread.Sleep(1000);
                }

                device.StopCapture();
                device.Close();
            }, stoppingToken);
        }
    }
}
