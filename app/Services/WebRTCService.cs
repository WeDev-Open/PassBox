using LZStringCSharp;
using Microsoft.JSInterop;
using Newtonsoft.Json;
using SIPSorcery.Net;
using System.Runtime.Intrinsics.Arm;

namespace PassboxApp.Services
{
    

    public class WebRTCService
    {
        private readonly IJSRuntime _jsRuntime;
        private RTCPeerConnection? _pc;

        public WebRTCService(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        public async Task InitConnection(string qrData)
        {
            var decompressed = LZString.DecompressFromBase64(qrData);
            var data = JsonConvert.DeserializeObject<QRData>(decompressed);

            _pc = new RTCPeerConnection();
            _pc.onconnectionstatechange += state =>
                Console.WriteLine($"Connection state: {state}");

            // 设置远程 Offer
            _pc.setRemoteDescription(data.Sdp);

            // 添加 ICE 候选
            foreach (var candidate in data.Candidates)
            {
                 _pc.addIceCandidate(candidate);
            }

            // 创建 Answer
            var answer = _pc.createAnswer();
            await _pc.setLocalDescription(answer);

            // 监听数据通道
            _pc.ondatachannel += channel =>
            {
                channel.onmessage += Channel_onmessage;
            };
        }

        private void Channel_onmessage(RTCDataChannel dc, DataChannelPayloadProtocols protocol, byte[] data)
        {
                   
        }

        private record QRData(RTCSessionDescriptionInit Sdp, List<RTCIceCandidateInit> Candidates);
    }
}
