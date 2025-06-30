using SharpPcap;
using SharpPcap.LibPcap;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace RouterDetector.CaptureConsole.Utilities
{
    public class LoadDevices
    {
        [DllImport("wlanapi.dll")]
        private static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport("wlanapi.dll")]
        private static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll")]
        private static extern void WlanFreeMemory(IntPtr pMemory);

        [DllImport("wlanapi.dll")]
        private static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("wlanapi.dll")]
        private static extern uint WlanQueryInterface(
            IntPtr hClientHandle,
            ref Guid interfaceGuid,
            WLAN_INTF_OPCODE opCode,
            IntPtr pReserved,
            out uint pdwDataSize,
            out IntPtr ppData,
            IntPtr pWlanOpcodeValueType);

        private const uint WLAN_CLIENT_VERSION_WINDOWS_7 = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;
            public WLAN_INTERFACE_STATE isState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public WLAN_INTERFACE_INFO[] InterfaceInfo;

            public static WLAN_INTERFACE_INFO_LIST FromPointer(IntPtr ppInterfaceList)
            {
                int offset = 0;
                var result = new WLAN_INTERFACE_INFO_LIST();

                // Read dwNumberOfItems
                result.dwNumberOfItems = (uint)Marshal.ReadInt32(ppInterfaceList, offset);
                offset += 4;

                // Read dwIndex
                result.dwIndex = (uint)Marshal.ReadInt32(ppInterfaceList, offset);
                offset += 4;

                // Create array of proper size
                result.InterfaceInfo = new WLAN_INTERFACE_INFO[result.dwNumberOfItems];

                // Read each interface info
                for (int i = 0; i < result.dwNumberOfItems; i++)
                {
                    IntPtr itemPtr = new IntPtr(ppInterfaceList.ToInt64() + offset + i * Marshal.SizeOf<WLAN_INTERFACE_INFO>());
                    result.InterfaceInfo[i] = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(itemPtr);
                }

                return result;
            }
        }

        public enum WLAN_INTERFACE_STATE : uint
        {
            wlan_interface_state_not_ready = 0,
            wlan_interface_state_connected = 1,
            wlan_interface_state_ad_hoc_network_formed = 2,
            wlan_interface_state_disconnecting = 3,
            wlan_interface_state_disconnected = 4,
            wlan_interface_state_associating = 5,
            wlan_interface_state_discovering = 6,
            wlan_interface_state_authenticating = 7
        }

        public enum WLAN_INTF_OPCODE : uint
        {
            wlan_intf_opcode_current_connection = 7
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_CONNECTION_ATTRIBUTES
        {
            public WLAN_INTERFACE_STATE isState;
            public WLAN_CONNECTION_MODE wlanConnectionMode;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strProfileName;
            public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
            public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
        }

        public enum WLAN_CONNECTION_MODE : uint
        {
            wlan_connection_mode_profile = 0,
            wlan_connection_mode_temporary_profile = 1,
            wlan_connection_mode_discovery_secure = 2,
            wlan_connection_mode_discovery_unsecure = 3,
            wlan_connection_mode_auto = 4,
            wlan_connection_mode_invalid = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_ASSOCIATION_ATTRIBUTES
        {
            public DOT11_SSID dot11Ssid;
            public DOT11_BSS_TYPE dot11BssType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] dot11Bssid;
            public DOT11_PHY_TYPE dot11PhyType;
            public uint uDot11PhyIndex;
            public uint wlanSignalQuality;
            public uint ulRxRate;
            public uint ulTxRate;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DOT11_SSID
        {
            public uint uSSIDLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] ucSSID;
        }

        public enum DOT11_BSS_TYPE : uint
        {
            dot11_BSS_type_infrastructure = 1,
            dot11_BSS_type_independent = 2,
            dot11_BSS_type_any = 3
        }

        public enum DOT11_PHY_TYPE : uint
        {
            dot11_phy_type_unknown = 0,
            dot11_phy_type_any = 0,
            dot11_phy_type_fhss = 1,
            dot11_phy_type_dsss = 2,
            dot11_phy_type_irbaseband = 3,
            dot11_phy_type_ofdm = 4,
            dot11_phy_type_hrdsss = 5,
            dot11_phy_type_erp = 6,
            dot11_phy_type_ht = 7,
            dot11_phy_type_vht = 8,
            dot11_phy_type_IHV_start = 0x80000000,
            dot11_phy_type_IHV_end = 0xffffffff
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_SECURITY_ATTRIBUTES
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool bSecurityEnabled;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bOneXEnabled;
            public DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;
            public DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
        }

        public enum DOT11_AUTH_ALGORITHM : uint
        {
            DOT11_AUTH_ALGO_80211_OPEN = 1,
            DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
            DOT11_AUTH_ALGO_WPA = 3,
            DOT11_AUTH_ALGO_WPA_PSK = 4,
            DOT11_AUTH_ALGO_WPA_NONE = 5,
            DOT11_AUTH_ALGO_RSNA = 6,
            DOT11_AUTH_ALGO_RSNA_PSK = 7,
            DOT11_AUTH_ALGO_IHV_START = 0x80000000,
            DOT11_AUTH_ALGO_IHV_END = 0xffffffff
        }

        public enum DOT11_CIPHER_ALGORITHM : uint
        {
            DOT11_CIPHER_ALGO_NONE = 0x00,
            DOT11_CIPHER_ALGO_WEP40 = 0x01,
            DOT11_CIPHER_ALGO_TKIP = 0x02,
            DOT11_CIPHER_ALGO_CCMP = 0x04,
            DOT11_CIPHER_ALGO_WEP104 = 0x05,
            DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
            DOT11_CIPHER_ALGO_WEP = 0x101,
            DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
            DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
        }

        public static string? GetWifiRouterName()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return null;
            }

            IntPtr clientHandle = IntPtr.Zero;
            IntPtr interfaceList = IntPtr.Zero;

            try
            {
                uint negotiatedVersion;
                uint result = WlanOpenHandle(WLAN_CLIENT_VERSION_WINDOWS_7, IntPtr.Zero, out negotiatedVersion, out clientHandle);
                if (result != 0)
                {
                    throw new Win32Exception((int)result);
                }

                result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList);
                if (result != 0)
                {
                    throw new Win32Exception((int)result);
                }

                if (interfaceList == IntPtr.Zero)
                {
                    return null;
                }

                var interfaceInfoList = WLAN_INTERFACE_INFO_LIST.FromPointer(interfaceList);

                for (int i = 0; i < interfaceInfoList.InterfaceInfo.Length; i++)
                {
                    var interfaceInfo = interfaceInfoList.InterfaceInfo[i];
                    if (interfaceInfo.isState == WLAN_INTERFACE_STATE.wlan_interface_state_connected)
                    {
                        uint dataSize;
                        IntPtr connectionAttributes;
                        result = WlanQueryInterface(
                            clientHandle,
                            ref interfaceInfoList.InterfaceInfo[i].InterfaceGuid,
                            WLAN_INTF_OPCODE.wlan_intf_opcode_current_connection,
                            IntPtr.Zero,
                            out dataSize,
                            out connectionAttributes,
                            IntPtr.Zero);

                        if (result == 0 && connectionAttributes != IntPtr.Zero)
                        {
                            try
                            {
                                var attributes = Marshal.PtrToStructure<WLAN_CONNECTION_ATTRIBUTES>(connectionAttributes);
                                var ssidLength = (int)attributes.wlanAssociationAttributes.dot11Ssid.uSSIDLength;
                                if (ssidLength > 0 && ssidLength <= 32)
                                {
                                    byte[] ssidBytes = new byte[ssidLength];
                                    Array.Copy(
                                        attributes.wlanAssociationAttributes.dot11Ssid.ucSSID,
                                        ssidBytes,
                                        ssidLength);

                                    return System.Text.Encoding.ASCII.GetString(ssidBytes);
                                }
                            }
                            finally
                            {
                                WlanFreeMemory(connectionAttributes);
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting WiFi router name: {ex.Message}");
                return null;
            }
            finally
            {
                if (interfaceList != IntPtr.Zero)
                {
                    WlanFreeMemory(interfaceList);
                }
                if (clientHandle != IntPtr.Zero)
                {
                    WlanCloseHandle(clientHandle, IntPtr.Zero);
                }
            }

            return null;
        }

        public static string? GetDefaultGateway()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                foreach (var netInterface in interfaces)
                {
                    Console.WriteLine($"Interface: {netInterface.Name}");
                    Console.WriteLine($"  Type: {netInterface.NetworkInterfaceType}");
                    Console.WriteLine($"  Status: {netInterface.OperationalStatus}");

                    var ipProps = netInterface.GetIPProperties();
                    if (ipProps == null)
                    {
                        Console.WriteLine("  No IP properties found.");
                        continue;
                    }

                    foreach (var gw in ipProps.GatewayAddresses)
                    {
                        Console.WriteLine($"  Gateway: {gw.Address}");
                    }
                }

                var gateway = interfaces
                    .Select(n => n.GetIPProperties())
                    .Where(ipProps => ipProps != null)
                    .SelectMany(ipProps => ipProps.GatewayAddresses)
                    .Where(gateway => gateway?.Address != null)
                    .OrderBy(gateway => gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    .Select(gateway => gateway.Address.ToString())
                    .FirstOrDefault();

                return gateway; // Will return null if none found
            }
            catch (NetworkInformationException ex)
            {
                Console.WriteLine($"NetworkInformationException: {ex.Message}");
                return null;
            }
        }

        public static Guid? GetConnectedWifiInterfaceGuid()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return null;
            }

            IntPtr clientHandle = IntPtr.Zero;
            IntPtr interfaceList = IntPtr.Zero;

            try
            {
                uint negotiatedVersion;
                uint result = WlanOpenHandle(WLAN_CLIENT_VERSION_WINDOWS_7, IntPtr.Zero, out negotiatedVersion, out clientHandle);
                if (result != 0)
                {
                    Console.WriteLine($"WlanOpenHandle failed with error: {new Win32Exception((int)result).Message}");
                    return null;
                }

                result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList);
                if (result != 0)
                {
                    Console.WriteLine($"WlanEnumInterfaces failed with error: {new Win32Exception((int)result).Message}");
                    return null;
                }

                if (interfaceList == IntPtr.Zero)
                {
                    return null;
                }

                var interfaceInfoList = WLAN_INTERFACE_INFO_LIST.FromPointer(interfaceList);

                for (int i = 0; i < interfaceInfoList.InterfaceInfo.Length; i++)
                {
                    var interfaceInfo = interfaceInfoList.InterfaceInfo[i];
                    if (interfaceInfo.isState == WLAN_INTERFACE_STATE.wlan_interface_state_connected)
                    {
                        return interfaceInfo.InterfaceGuid;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting WiFi interface GUID: {ex.Message}");
                return null;
            }
            finally
            {
                if (interfaceList != IntPtr.Zero)
                {
                    WlanFreeMemory(interfaceList);
                }
                if (clientHandle != IntPtr.Zero)
                {
                    WlanCloseHandle(clientHandle, IntPtr.Zero);
                }
            }

            return null;
        }

        public static ICaptureDevice? SelectDevice()
        {
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found. Make sure you're running as administrator.");
                return null;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var wifiGuid = GetConnectedWifiInterfaceGuid();
                if (wifiGuid.HasValue)
                {
                    foreach (var device in devices)
                    {
                        const string npfPrefix = @"\Device\NPF_";
                        if (device.Name.StartsWith(npfPrefix))
                        {
                            var deviceGuidString = device.Name.Substring(npfPrefix.Length);
                            if (Guid.TryParse(deviceGuidString, out Guid deviceGuid))
                            {
                                if (deviceGuid == wifiGuid.Value)
                                {
                                    Console.WriteLine($"Automatically selected Wi-Fi device: {device.Description}");
                                    return device;
                                }
                            }
                        }
                    }
                }
            }

            Console.WriteLine();
            GetDefaultGateway();
            Console.WriteLine("\nAvailable network devices:");
            for (int i = 0; i < devices.Count; i++)
            {
                if (devices[i] is LibPcapLiveDevice pcapLiveDevice)
                {
                    Console.WriteLine($"{i}: {pcapLiveDevice.Description}");
                }
                else
                {
                    Console.WriteLine($"{i}: {devices[i].Description}");
                }
            }

            Console.Write("\nEnter device number: ");
            if (int.TryParse(Console.ReadLine(), out int selectedIndex))
            {
                if (selectedIndex >= 0 && selectedIndex < devices.Count)
                {
                    var selectedDevice = devices[selectedIndex];
                    return selectedDevice;
                }
            }

            Console.WriteLine("Invalid selection.");
            return null;
        }

    }




}