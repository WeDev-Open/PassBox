using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PassboxApp.Services
{
    public interface INetworkService
    {
        List<byte[]> GetLocalIPAddresses();
        Task<List<byte[]>> GetLocalIPAddressesAsync();

    }

    public static class NetworkHelper
    {
        //public static IPAddress GetIpAddress()
        //{
        //    // Up, Ethernet and IP4.
        //    var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
        //        .Where(network => network.OperationalStatus == OperationalStatus.Up &&
        //            (network.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
        //                network.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) &&
        //            network.GetIPProperties().UnicastAddresses
        //                .Where(ai => ai.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        //                .Count() > 0)
        //        .ToArray();
        //    if (networkInterfaces.Count() == 0)
        //        return null;

        //    var addressInfos = networkInterfaces[0].GetIPProperties().UnicastAddresses
        //        .Where(ai => ai.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
        //            !ai.Address.ToString().StartsWith("169"))
        //        .ToArray();
        //    if (addressInfos.Count() == 0)
        //        return null;

        //    return addressInfos[0].Address;
        //}

        public static IPAddress GetIpAddress()
        {
            var lanIPs = new List<IPAddress>();

            try
            {
                foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    // 强化接口过滤条件
                    if (netInterface.OperationalStatus != OperationalStatus.Up ||
                        (netInterface.NetworkInterfaceType != NetworkInterfaceType.Wireless80211 &&
                         netInterface.NetworkInterfaceType != NetworkInterfaceType.Ethernet))
                        continue;

                    foreach (var ipInfo in netInterface.GetIPProperties().UnicastAddresses)
                    {
                        if (ipInfo.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;

                        byte[] bytes = ipInfo.Address.GetAddressBytes();

                        // 排除 APIPA 地址（性能优化版）
                        if (bytes[0] == 169 && bytes[1] == 254)
                            continue;

                        if (IsPrivateIP(bytes))
                        {
                            lanIPs.Add(ipInfo.Address);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"IP 获取失败: {ex.Message}");
                throw ex;
            }

            return lanIPs.FirstOrDefault();
        }

        // 优化后的私有 IP 判断（直接操作字节数组）
        private static bool IsPrivateIP(byte[] bytes)
        {
            if (bytes.Length != 4) return false;

            return bytes[0] switch
            {
                10 => true,
                172 when bytes[1] >= 16 && bytes[1] <= 31 => true,
                192 when bytes[1] == 168 => true,
                _ => false
            };
        }
    }
}
