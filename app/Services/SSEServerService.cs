using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace PassboxApp.Services
{
    public class SSEServerService
    {
        private string selectedData = null; // 存储选中的数据

        public int Port { get; set; } = 5000;

        public IPAddress IP { get; set; }

        public IPEndPoint? ServerIpEndpoint { get; set; }

        private IWebHost? Host { get; set; }

        private bool _keepSend = true;

        private readonly RSA _rsa;
        private readonly RSA? _rsaB;
        private readonly string _publicKey;
        private readonly string _privateKey;
        private readonly Dictionary<string,string> _aesKeys;

        private readonly List<string> _sseCons;

        public Action<string>? ShowMsg { get; set; }

        private INetworkService _network;
        public SSEServerService(INetworkService network)
        { 
            _network = network;
            //生成公钥 发送给客户端
            _rsa = RSA.Create(2048);
             var xmlPublicKey = _rsa.ToXmlString(false);
            _publicKey =Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlPublicKey));

            //生成私钥 发送给客户端
            _rsaB = RSA.Create(2048);
            var pemKey= _rsaB.ExportPkcs8PrivateKeyPem();
            _privateKey = Convert.ToBase64String(Encoding.UTF8.GetBytes(pemKey));
            _aesKeys = [];
            _sseCons = [];


        }

        public async Task StartServer()
        {
            _keepSend=true;
            if (Host != null)
            {
                ShowMsg("Server Started");
                return;
            }

            try
            {
                var ipBytes= _network.GetLocalIPAddresses().FirstOrDefault();
                IP = new IPAddress(ipBytes);
                Port = Random.Shared.Next(9000, 9999);
                ServerIpEndpoint = new IPEndPoint(IP, Port);
            }
            catch (Exception ex)
            {
                ShowMsg($"Network error:{ex.Message}");
            }
           

            Host = new WebHostBuilder()
                            .ConfigureAppConfiguration((config) =>
                            {
                                //config.AddEmbeddedResource(
                                //    new EmbeddedResourceConfigurationOptions
                                //    {
                                //        Assembly = Assembly.GetExecutingAssembly(),
                                //        Prefix = "DemoApp.WebHost"
                                //    });
                            })
                            .ConfigureServices((hostContext, services) =>
                            {
                                services.AddSingleton<IHostLifetime, ConsoleLifetimePatch>();
                            })
                            .UseKestrel(options =>
                            {
                                options.Listen(ServerIpEndpoint);
                                //options.Listen(ServerIpEndpoint, options =>
                                //{
                                //    options.UseHttps();
                                //});

                            })
                            .UseContentRoot(Directory.GetCurrentDirectory())
                            //.UseStartup<Startup>()
                            .Configure(app =>
                            {
                                //GET AES key
                                app.Map("/cry", cryApp =>
                                {
                                    cryApp.Run(async context =>
                                    {
                                        var request=context.Request;
                                        var response=context.Response;
                                        var headers= request.Headers;

                                        if (request.Method==HttpMethod.Post.Method && headers.ContainsKey("Content-Type") && headers["Content-Type"]=="application/json")
                                        {
                                            try
                                            {
                                                var query = request.Query;

                                                if (query.ContainsKey("clientid"))
                                                {
                                                    var clientId = request.Query["clientid"].ToString();

                                                    // 从请求体中读取数
                                                    using var reader = new StreamReader(request.Body);

                                                    var encryParam = await reader.ReadToEndAsync();
                                                    // 根据 encryParam 解析 AES 密钥，然后添加到 _aesKeys
                                                    //
                                                    var keyObj = JsonConvert.DeserializeObject<EncryptedKeyModel>(encryParam);

                                                    var encryAeskeyBytes = Convert.FromBase64String(keyObj.Key);
                                                    var aesKeyBytes = _rsa.Decrypt(encryAeskeyBytes, RSAEncryptionPadding.OaepSHA256);
                                                    var aesKey = Encoding.UTF8.GetString(aesKeyBytes);

                                                    if (!_aesKeys.ContainsKey(clientId))
                                                    {
                                                        _aesKeys.Add(clientId, aesKey);
                                                    }
                                                    else
                                                    {
                                                        _aesKeys[clientId] = aesKey;
                                                    }
                                                }

                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine(ex.ToString());
                                            }
                                            
                                        }

                                        response.StatusCode = (int)HttpStatusCode.OK;

                                    });
                                });


                                app.Map("/sse", sseApp =>
                                {
                                    sseApp.Run(async context =>
                                    {
                                        var request = context.Request;
                                        var response = context.Response;
                                       

                                        var query = request.Query;

                                        if (query.ContainsKey("clientid") && query.ContainsKey("tabid"))
                                        {
                                            var clientId = request.Query["clientid"].ToString();
                                            var tabId= request.Query["tabid"].ToString();

                                            var conId=$"{clientId}-{tabId}";

                                            if (_sseCons.Contains(conId))
                                            {
                                                response.StatusCode = 429;
                                                //已存在相同连接，不进行sse
                                                await response.WriteAsync("data:999999\n\n");
                                                ShowMsg("Client request again, can send.");
                                                return;
                                            }

                                            response.ContentType = "text/event-stream";
                                            response.Headers.Append("Cache-Control", "no-cache");
                                            response.Headers.Append("Connection", "keep-alive");
                                            response.Headers.Append("Access-Control-Allow-Origin", "*");

                                            _sseCons.Add(conId);

                                            ShowMsg("Connection successful, can send.");

                                            //int counter = 0;
                                            while (!context.RequestAborted.IsCancellationRequested && _keepSend)
                                            {
                                                string data = $"data: {DateTime.UtcNow.Ticks}\n\n";

                                                try
                                                {
                                                    

                                                    if (!string.IsNullOrWhiteSpace(selectedData))
                                                    {
                                                        //对数据加密
                                                        //获取aes 密钥，对数据加密
                                                        var aesKey = _aesKeys[clientId];
                                                        var aesResult = EncryptWithAesGcm(selectedData, aesKey);

                                                        // 3. 使用 RSA-OAEP(SHA-256) 用客户端公钥（密钥对 B 公钥）加密 AES 密钥
                                                        byte[] encryptedAesKey = RSAEncryptAesKey(aesKey);

                                                        // 4. 使用服务器签名私钥（密钥对 A 私钥）对加密后的消息（密文）进行签名
                                                        byte[] signature = SignData(aesResult.Ciphertext);
                                                        // 5. 生成 SSE 消息的 JSON 载荷
                                                        var payload = new
                                                        {
                                                            tabId,
                                                            clientId,
                                                            data = new
                                                            {
                                                                AESKey = Convert.ToBase64String(encryptedAesKey),
                                                                Encrypted = Convert.ToBase64String(aesResult.Ciphertext),
                                                                IV = Convert.ToBase64String(aesResult.IV),
                                                                Tag = Convert.ToBase64String(aesResult.Tag),
                                                                Signature = Convert.ToBase64String(signature)
                                                            }
                                                        };

                                                        string jsonPayload = JsonConvert.SerializeObject(payload);
                                                        string base64String = Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonPayload));

                                                        data = $"data: {base64String}\n\n";
                                                    }

                                                }
                                                catch (Exception ex)
                                                {
                                                    Console.WriteLine(ex.Message);
                                                }

                                                await response.WriteAsync(data);
                                                await response.Body.FlushAsync();

                                                if (!string.IsNullOrWhiteSpace(selectedData))
                                                {
                                                    selectedData = null;
                                                    //_keepSend = false;
                                                }
                                                await Task.Delay(2000);
                                            }

                                        }
                                       
                                    });
                                });

                                // 处理根路径
                                app.Run(async context =>
                                {
                                    var response = context.Response;
                                    response.Headers.Append("pass", _publicKey);
                                    response.Headers.Append("passb", _privateKey);

                                    await context.Response.WriteAsync("Hello from Passbox!");

                                    ShowMsg("Client accessed.");
                                });
                                
                                
                            })
                            //.ConfigureServices()
                            .Build();
                Host.RunPatchedAsync();

            ShowMsg("Server Started.");
        }

        public void StopSend()
        {
            _keepSend = false;
        }
        public void UpdateSelectedData(string data)
        {
            _keepSend= true;
            selectedData = data;
        }

        private (byte[] Ciphertext, byte[] IV, byte[] Tag) EncryptWithAesGcm(string plaintext,string key)
        { 
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var keyBytes = Convert.FromBase64String(key);
           // var keyBytes=Encoding.UTF8.GetBytes(key);

            byte[] iv=new byte[12];
            RandomNumberGenerator.Fill(iv);

            byte[] ciphertext=new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            using var aesGcm = new AesGcm(keyBytes,AesGcm.TagByteSizes.MaxSize);
            aesGcm.Encrypt(iv, plaintextBytes, ciphertext,tag);

            return (ciphertext, iv, tag);
        
        }

        /// <summary>
        /// 使用 RSA-OAEP(SHA-256) 加密 AES 密钥
        /// </summary>
        private byte[] RSAEncryptAesKey(string aesKey)
        {
            //var aesKeyBytes=Encoding.UTF8.GetBytes(aesKey);
            var aesKeyBytes = Convert.FromBase64String(aesKey);
            return _rsaB.Encrypt(aesKeyBytes, RSAEncryptionPadding.OaepSHA256);
        }

        /// <summary>
        /// 使用 RSA 签名（RSASSA-PKCS1-v1_5 + SHA256）对数据签名
        /// </summary>
        private byte[] SignData(byte[] data)
        {
            return _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public class EncryptedKeyModel
    {
        public string Key { get; set; }
    }
}
