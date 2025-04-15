using Android.Content;
using Android.Locations;
using Android.Net;
using Android.Util;
using PassboxApp.Services;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;

namespace PassboxApp.Platforms.Android
{
    public class NetworkService : INetworkService
    {
        private const string TAG = "NetworkService";
        private readonly HashSet<byte[]> ips = new();

        public List<byte[]> GetLocalIPAddresses()
        {
            ips.Clear();

            try
            {
                // 方案1：通过 ConnectivityManager
                var connectivityManager = (ConnectivityManager)Platform.AppContext.GetSystemService(Context.ConnectivityService);
                var allNetworks = connectivityManager.GetAllNetworks();
                foreach (var network in allNetworks)
                {
                    var capabilities = connectivityManager.GetNetworkCapabilities(network);
                    var linkProperties = connectivityManager.GetLinkProperties(network);

                    if (capabilities == null || linkProperties == null) continue;

                    if (capabilities.HasTransport(TransportType.Wifi) ||
                        capabilities.HasTransport(TransportType.Ethernet))
                    {
                        foreach (var address in linkProperties.LinkAddresses)
                        {
                            //var ip = address.Address?.HostAddress;
                            //if (IsLocalIP(ip))
                            //{
                            //    ips.Add(ip);
                            //}
                            var ipBytes = address.Address.GetAddress();//?.HostAddress;

                            if (IsLocalIP(ipBytes))
                            {
                                ips.Add(ipBytes);
                            }
                        }
                    }
                }

                // 方案2：通过 NetworkInterface（备用）
                if (ips.Count == 0)
                {
                    var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                        .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                   !n.Description.Contains("virtual", StringComparison.OrdinalIgnoreCase));

                    foreach (var ni in interfaces)
                    {
                        foreach (var ip in ni.GetIPProperties().UnicastAddresses
                                 .Select(x => x.Address))
                        {
                            var ipBytes = ip.GetAddressBytes();
                            if (IsLocalIP(ipBytes))
                            {
                                ips.Add(ipBytes);
                            }
                        }
                        //foreach (var ip in ni.GetIPProperties().UnicastAddresses
                        //         .Select(x => x.Address.ToString()))
                        //{
                        //    if (IsLocalIP(ip))
                        //    {
                        //        ips.Add(ip);
                        //    }
                        //}
                    }
                }
            }
            catch (SecurityException ex)
            {
                Log.Error(TAG, $"Insufficient permissions: {ex.Message}");
            }
            catch (Exception ex)
            {
                Log.Error(TAG, $"Network query exception: {ex}");
            }
            return ips.Distinct().ToList();
        }

        private bool IsLocalIP(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;

            // 处理 IPv6 本地链路地址
            if (ip.StartsWith("fe80", StringComparison.OrdinalIgnoreCase)) return false; // 排除 IPv6

            // IPv4 判断
            if (ip.Contains(':')) return false; // 排除 IPv6

            var parts = ip.Split('.');
            if (parts.Length != 4) return false;

            return parts[0] switch
            {
                "10" => true,
                "172" => int.Parse(parts[1]) >= 16 && int.Parse(parts[1]) <= 31,
                "192" => parts[1] == "168",
                _ => false
            };
        }

        private bool IsLocalIP(byte[] ipBytes)
        {
            if (ipBytes == null) return false;

            if (ipBytes.Length != 4) return false;//排除v6

            if (IsAPIPA(ipBytes)) return false;

            if (IsPrivateIP(ipBytes)) return true;

            return false;
        }

        private  bool IsAPIPA(byte[] ipBytes)
        {
            return ipBytes[0] == 169 && ipBytes[1] == 254;
        }

        private  bool IsPrivateIP(byte[] ipBytes)
        {
            return ipBytes[0] switch
            {
                10 => true,
                172 when ipBytes[1] >= 16 && ipBytes[1] <= 31 => true,
                192 when ipBytes[1] == 168 => true,
                _ => false
            };
        }

        public async Task<List<byte[]>> GetLocalIPAddressesAsync()
        {
            return await Task.Run(GetLocalIPAddresses);
        }
    }
}
