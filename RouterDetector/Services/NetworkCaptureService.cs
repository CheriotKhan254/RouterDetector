using PacketDotNet;
using RouterDetector.Data;
using RouterDetector.Models;
using SharpPcap;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RouterDetector.Services
{
    public class NetworkCaptureService : INetworkCaptureService, IDisposable
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<NetworkCaptureService> _logger;
        private ICaptureDevice? _currentDevice;
        private bool _disposed;
        private readonly object _lock = new();

        public bool IsRunning { get; private set; }
        public string? CurrentDevice { get; private set; }
        public string? RouterIp { get; }

        public NetworkCaptureService(IServiceProvider serviceProvider, ILogger<NetworkCaptureService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            RouterIp = GetDefaultGateway();
            _logger.LogInformation($"Router IP detected: {RouterIp ?? "None"}");

            IsRunning = false;
            CurrentDevice = null;
            _currentDevice = null;
        }

        public IEnumerable<CaptureDeviceInfo> GetAvailableDevices()
        {
            var devices = CaptureDeviceList.Instance
                .Select(d => new CaptureDeviceInfo
                {
                    Name = d.Name,
                    Description = d.Description
                }).ToList();

            _logger.LogInformation($"Found {devices.Count} capture devices");
            return devices;
        }

        public async Task StartCaptureAsync(string? deviceName = null)
        {
            if (IsRunning)
            {
                _logger.LogWarning("Capture is already running");
                return;
            }

            await Task.Run(() =>
            {
                lock (_lock)
                {
                    _currentDevice = FindCaptureDevice(deviceName);

                    if (_currentDevice == null)
                    {
                        _logger.LogError("No suitable network device found");
                        throw new InvalidOperationException("No suitable network device found");
                    }

                    try
                    {
                        _logger.LogInformation($"Opening device: {_currentDevice.Description}");

                        // Use the same approach as your working console version
                        _currentDevice.OnPacketArrival += OnPacketArrival;
                        _currentDevice.Open(DeviceModes.Promiscuous, 1000); // Match console version
                        _currentDevice.StartCapture();

                        CurrentDevice = _currentDevice.Description;
                        IsRunning = true;
                        _logger.LogInformation($"Started packet capture on device: {CurrentDevice}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Failed to start capture on device: {_currentDevice.Description}");
                        CleanupDevice();
                        throw;
                    }
                }
            });
        }

        public async Task StopCaptureAsync()
        {
            if (!IsRunning) return;

            await Task.Run(() =>
            {
                lock (_lock)
                {
                    CleanupDevice();
                    CurrentDevice = null;
                    IsRunning = false;
                    _logger.LogInformation("Packet capture stopped");
                }
            });
        }

        private void CleanupDevice()
        {
            try
            {
                if (_currentDevice != null)
                {
                    _logger.LogInformation("Stopping packet capture");

                    if (_currentDevice.Started)
                    {
                        _currentDevice.StopCapture();
                    }

                    _currentDevice.OnPacketArrival -= OnPacketArrival;
                    _currentDevice.Close();
                    _currentDevice = null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during device cleanup");
            }
        }

        private ICaptureDevice? FindCaptureDevice(string? deviceName)
        {
            var devices = CaptureDeviceList.Instance;
            _logger.LogInformation($"Looking for capture device. Total devices: {devices.Count}");

            if (!string.IsNullOrEmpty(deviceName))
            {
                var device = devices.FirstOrDefault(d =>
                    d.Name.Equals(deviceName, StringComparison.OrdinalIgnoreCase) ||
                    d.Description.Equals(deviceName, StringComparison.OrdinalIgnoreCase));

                if (device != null)
                {
                    _logger.LogInformation($"Found specific device: {device.Description}");
                    return device;
                }
            }

            // Use the same logic as your working console version
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up &&
                    (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                     nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet))
                {
                    var ipProps = nic.GetIPProperties();
                    var ip = ipProps.UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

                    if (ip != null)
                    {
                        var device = devices.FirstOrDefault(d =>
                            d.Description.Contains(nic.Description, StringComparison.OrdinalIgnoreCase));
                        if (device != null)
                        {
                            _logger.LogInformation($"Selected device: {device.Description}");
                            return device;
                        }
                    }
                }
            }

            // Fallback to first device if no match found
            var firstDevice = devices.FirstOrDefault();
            if (firstDevice != null)
            {
                _logger.LogWarning($"No ideal device found, using first available: {firstDevice.Description}");
            }
            return firstDevice;
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var rawCapture = e.GetPacket();
                // Use the same parsing approach as your working console version
                var packet = Packet.ParsePacket(LinkLayers.Ethernet, rawCapture.Data);

                var ethernet = packet.Extract<EthernetPacket>();
                var ipPacket = packet.Extract<IPPacket>();
                var tcpPacket = packet.Extract<TcpPacket>();
                var udpPacket = packet.Extract<UdpPacket>();

                if (ipPacket == null)
                {
                    return; // Skip non-IP packets
                }

                // REMOVED the restrictive router IP filtering that was preventing packet capture
                // The console version doesn't filter by router IP, so we'll capture all traffic
                _logger.LogTrace($"Processing packet: {ipPacket.SourceAddress} -> {ipPacket.DestinationAddress}");
                ProcessPacket(rawCapture, ipPacket, tcpPacket, udpPacket);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing packet");
            }
        }

        private void ProcessPacket(RawCapture rawCapture, IPPacket ipPacket, TcpPacket? tcpPacket, UdpPacket? udpPacket)
        {
            try
            {
                string protocol = tcpPacket != null ? "TCP" : udpPacket != null ? "UDP" : ipPacket.Protocol.ToString();
                int sourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
                int destPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;

                // Detection logic - you can expand this
                bool isMalicious = destPort == 22; // SSH detection

                // Detect application protocol like in console version
                string appProtocol = DetectApplicationProtocol(sourcePort, destPort);

                using var scope = _serviceProvider.CreateScope();
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
                    Message = isMalicious ? "Malicious SSH attempt detected" : $"Normal {appProtocol} traffic",
                    LogOccurrence = rawCapture.Timeval.Date // Use actual packet timestamp
                };

                db.Networklogs.Add(traffic);
                db.SaveChanges();

                _logger.LogDebug($"Saved network log: {traffic.SrcIp}:{traffic.SrcPort} -> {traffic.DstIp}:{traffic.DstPort} ({appProtocol})");

                if (isMalicious)
                {
                    var detection = new Detectionlogs
                    {
                        Timestamp = rawCapture.Timeval.Date,
                        Institution = "N/A",
                        SourceIP = ipPacket.SourceAddress.ToString(),
                        DeviceType = "Router",
                        LogSource = "PCAP",
                        EventType = "SSH Brute Force",
                        Severty = "High",
                        ActionTaken = "Blocked",
                        Notes = "Detected by packet capture"
                    };

                    db.Detectionlogs.Add(detection);
                    db.SaveChanges();
                    _logger.LogWarning($"Malicious activity detected and logged: SSH attempt from {ipPacket.SourceAddress}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving packet to database");
            }
        }

        private static string DetectApplicationProtocol(int srcPort, int dstPort)
        {
            var knownPorts = new Dictionary<int, string>
            {
                [80] = "HTTP",
                [443] = "HTTPS",
                [53] = "DNS",
                [25] = "SMTP",
                [110] = "POP3",
                [143] = "IMAP",
                [21] = "FTP",
                [123] = "NTP",
                [161] = "SNMP",
                [22] = "SSH",
                [3389] = "RDP",
                [1900] = "SSDP"
            };

            if (knownPorts.TryGetValue(srcPort, out var protocol))
                return protocol;
            if (knownPorts.TryGetValue(dstPort, out protocol))
                return protocol;

            return "Unknown";
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                var gateway = NetworkInterface
                    .GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(n => n.GetIPProperties())
                    .Where(ipProps => ipProps != null)
                    .SelectMany(ipProps => ipProps.GatewayAddresses)
                    .Where(gateway => gateway?.Address != null)
                    .OrderBy(gateway => gateway.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    .Select(gateway => gateway.Address.ToString())
                    .FirstOrDefault();

                return gateway ?? "192.168.1.1"; // Fallback IP
            }
            catch (NetworkInformationException)
            {
                return "192.168.1.1"; // Fallback IP if any network info access fails
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                StopCaptureAsync().Wait();
                _currentDevice?.Dispose();
                _disposed = true;
            }
        }
    }
}