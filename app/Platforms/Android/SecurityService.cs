using System.Text;
using Android.App;
using Android.Content;
using Android.OS;
using Android.Security.Keystore;
using AndroidX.Biometric;
using Java.Security;
using Java.Util.Concurrent;
using Javax.Crypto;
using Javax.Crypto.Spec;
using PassboxApp.Services;
using Xamarin.Google.Crypto.Tink.Subtle;
using static Android.Graphics.ImageDecoder;
using Application = Android.App.Application;

namespace PassboxApp.Platforms.Android
{
    public class CallbackResult
    {
        public bool IsSucceeded { get; set; }

        public string Msg { get; set; }
    }
    public class BiometricAuthenticationCallback : BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<CallbackResult> _tcs;

        public BiometricAuthenticationCallback(TaskCompletionSource<CallbackResult> tcs)
        {
            _tcs = tcs;
        }

        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
        {
            base.OnAuthenticationSucceeded(result);
            _tcs.SetResult(new CallbackResult { IsSucceeded=true}); // 身份验证成功
        }

        public override void OnAuthenticationFailed()
        {
            base.OnAuthenticationFailed();
            _tcs.SetResult(new CallbackResult { IsSucceeded = false,Msg= "Failed" }); // 身份验证失败
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString)
        {
            base.OnAuthenticationError(errorCode, errString);
            string errorMessage = errorCode switch
            {
                BiometricPrompt.ErrorCanceled => "Authentication canceled.",
                BiometricPrompt.ErrorLockout => "Too many failed attempts. Please try again later.",
                BiometricPrompt.ErrorLockoutPermanent => "Biometric authentication is locked out permanently.",
                _ => errString.ToString()
            };
            _tcs.SetResult(new CallbackResult { IsSucceeded = false, Msg = errorMessage }); // 身份验证出错
        }
    }

    public class SecurityService : ISecurityService
    {
        // 获取 BiometricManager 实例
        BiometricManager biometricManager ;
        private TaskCompletionSource<CallbackResult> _tcs;
        public SecurityService()
        {
            biometricManager = BiometricManager.From(context: Platform.CurrentActivity.ApplicationContext);
        }

        public Task<CallbackResult> AuthenticateAsync(string reson= "Please fingerprint or enter device password", bool isAllowAlternativeAuthentication=true)
        {
            try
            {
                _tcs = new TaskCompletionSource<CallbackResult>();
                if (!IsBiometricAuthenticationAvailable()||!IsLockScreenPasswordSet())
                {
                    _tcs.SetResult(new CallbackResult { IsSucceeded=false,Msg= "Please set fingerprint recognition or lock screen password first, then try again." });
                    return _tcs.Task;
                }

                // 获取当前 Activity
                var activity = (AndroidX.Fragment.App.FragmentActivity)Platform.CurrentActivity;

                var executor = Executors.NewSingleThreadExecutor();

                // 用户认证后解密数据
                var biometricPrompt = new AndroidX.Biometric.BiometricPrompt(activity, executor, new BiometricAuthenticationCallback(_tcs));

                var builder = new AndroidX.Biometric.BiometricPrompt.PromptInfo.Builder()
                    .SetTitle("Identity Authentication")
                    .SetDescription(reson)
                   .SetConfirmationRequired(true);

                if (isAllowAlternativeAuthentication)
                {
                    // It's not allowed to allow alternative auth & set the negative button
                    builder = builder.SetDeviceCredentialAllowed(true);
                }
                else
                {
                    builder = builder.SetNegativeButtonText("Cancel");
                }

                var promptInfo = builder.Build();

                biometricPrompt.Authenticate(promptInfo);
            }
            catch (Exception ex)
            {
                Console.WriteLine("异常：" + ex.ToString());
                _tcs.SetResult(new CallbackResult { IsSucceeded = false, Msg = "Exception" });
                _tcs.SetException(ex);
                return _tcs.Task;
            }

            return _tcs.Task;
        }

        public string? Decrypt(string alias, string data)
        {
            byte[] encryptedDataWithIv = null;
            byte[] iv = new byte[12]; // GCM IV 固定为12字节
            byte[] encryptedDataWithTag = null;
            byte[] decryptedData = null;

            try
            {
                // 1. Base64解码输入数据
                encryptedDataWithIv = Convert.FromBase64String(data);
                if (encryptedDataWithIv.Length < iv.Length + 1) // 至少包含IV + 1字节密文+标签
                {
                    throw new ArgumentException("Invalid encrypted data format");
                }

                // 2. 分离IV和密文+标签
                Buffer.BlockCopy(encryptedDataWithIv, 0, iv, 0, iv.Length);
                encryptedDataWithTag = new byte[encryptedDataWithIv.Length - iv.Length];
                Buffer.BlockCopy(encryptedDataWithIv, iv.Length, encryptedDataWithTag, 0, encryptedDataWithTag.Length);

                // 3. 获取密钥（触发用户身份验证）
                var keyStore = KeyStore.GetInstance("AndroidKeyStore");
                keyStore.Load(null);
                var secretKeyEntry = (KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null);
                if (secretKeyEntry == null)
                {
                    throw new InvalidOperationException($"Key '{alias}' does not exist");
                }
                var secretKey = secretKeyEntry.SecretKey;

                // 4. 初始化Cipher并验证认证标签
                var cipher = Cipher.GetInstance("AES/GCM/NoPadding");
                var parameterSpec = new GCMParameterSpec(128, iv); // 128位标签
                cipher.Init(CipherMode.DecryptMode, secretKey, parameterSpec);

                // 5. 解密并验证完整性
                decryptedData = cipher.DoFinal(encryptedDataWithTag);

                // 6. 返回明文
                return Encoding.UTF8.GetString(decryptedData);
            }
            catch (KeyStoreException ex) when (ex.InnerException is KeyPermanentlyInvalidatedException)
            {
                // 密钥已失效（如生物识别信息变更）
                //throw new SecurityException("密钥已失效，需重新生成", ex);
                Console.WriteLine("密钥已失效，需重新生成", ex);
            }
            catch (Exception ex)
            {
                // 记录完整错误（生产环境应使用日志库）
                Console.WriteLine($"解密失败: {ex}");
                //throw new InvalidOperationException("数据解密失败", ex);
            }
            finally
            {
                // 7. 清理内存中的敏感数据
                if (encryptedDataWithIv != null)
                    Array.Clear(encryptedDataWithIv, 0, encryptedDataWithIv.Length);
                Array.Clear(iv, 0, iv.Length);
                if (encryptedDataWithTag != null)
                    Array.Clear(encryptedDataWithTag, 0, encryptedDataWithTag.Length);
                if (decryptedData != null)
                    Array.Clear(decryptedData, 0, decryptedData.Length);
            }

            return null;
        }

        public byte[]? DecryptByte(string alias, string data)
        {
            byte[] encryptedDataWithIv = null;
            byte[] iv = new byte[12]; // GCM IV 固定为12字节
            byte[] encryptedDataWithTag = null;
            byte[] decryptedData = null;

            try
            {
                // 1. Base64解码输入数据
                encryptedDataWithIv = Convert.FromBase64String(data);
                if (encryptedDataWithIv.Length < iv.Length + 1) // 至少包含IV + 1字节密文+标签
                {
                    throw new ArgumentException("Invalid encrypted data format");
                }

                // 2. 分离IV和密文+标签
                Buffer.BlockCopy(encryptedDataWithIv, 0, iv, 0, iv.Length);
                encryptedDataWithTag = new byte[encryptedDataWithIv.Length - iv.Length];
                Buffer.BlockCopy(encryptedDataWithIv, iv.Length, encryptedDataWithTag, 0, encryptedDataWithTag.Length);

                // 3. 获取密钥（触发用户身份验证）
                var keyStore = KeyStore.GetInstance("AndroidKeyStore");
                keyStore.Load(null);
                var secretKeyEntry = (KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null);
                if (secretKeyEntry == null)
                {
                    throw new InvalidOperationException($"Key '{alias}' does not exist");
                }
                var secretKey = secretKeyEntry.SecretKey;

                // 4. 初始化Cipher并验证认证标签
                var cipher = Cipher.GetInstance("AES/GCM/NoPadding");
                var parameterSpec = new GCMParameterSpec(128, iv); // 128位标签
                cipher.Init(CipherMode.DecryptMode, secretKey, parameterSpec);

                // 5. 解密并验证完整性
                decryptedData = cipher.DoFinal(encryptedDataWithTag);

                // 6. 返回明文
                return decryptedData;
            }
            catch (KeyStoreException ex) when (ex.InnerException is KeyPermanentlyInvalidatedException)
            {
                // 密钥已失效（如生物识别信息变更）
                //throw new SecurityException("密钥已失效，需重新生成", ex);
                Console.WriteLine("密钥已失效，需重新生成", ex);
            }
            catch (Exception ex)
            {
                // 记录完整错误（生产环境应使用日志库）
                Console.WriteLine($"解密失败: {ex}");
                //throw new InvalidOperationException("数据解密失败", ex);
            }
            finally
            {
                // 7. 清理内存中的敏感数据
                if (encryptedDataWithIv != null)
                    Array.Clear(encryptedDataWithIv, 0, encryptedDataWithIv.Length);
                Array.Clear(iv, 0, iv.Length);
                if (encryptedDataWithTag != null)
                    Array.Clear(encryptedDataWithTag, 0, encryptedDataWithTag.Length);
                if (decryptedData != null)
                    Array.Clear(decryptedData, 0, decryptedData.Length);
            }

            return null;
        }

        //public string? Encrypt(string alias, string data)
        //{
        //    byte[] encryptedData = null;
        //    byte[] iv = new byte[12]; // GCM推荐12字节IV

        //    try
        //    {
        //        var keyStore = KeyStore.GetInstance("AndroidKeyStore");
        //        keyStore.Load(null);

        //        // 1. 密钥生成配置强化（明确密钥长度和安全性参数）
        //        if (!keyStore.ContainsAlias(alias))
        //        {
        //            var keyGenerator = KeyGenerator.GetInstance(
        //                KeyProperties.KeyAlgorithmAes,
        //                "AndroidKeyStore"
        //            );

        //            var keyGenSpec = new KeyGenParameterSpec.Builder(
        //                alias,
        //                KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt
        //            )
        //                .SetBlockModes(KeyProperties.BlockModeGcm)
        //                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
        //                .SetKeySize(256) // 强制使用256位密钥
        //                .SetUserAuthenticationRequired(true)
        //                // 移除 SetUserAuthenticationValidityDurationSeconds，要求每次使用都认证
        //                .Build();

        //            keyGenerator.Init(keyGenSpec);
        //            keyGenerator.GenerateKey();
        //        }

        //        // 2. 获取密钥并初始化Cipher
        //        var secretKey = ((KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null)).SecretKey;
        //        var cipher = Cipher.GetInstance("AES/GCM/NoPadding");

        //        // 3. 显式生成安全的IV（替代cipher.GetIV()）
        //        //using (var secureRandom = new SecureRandom())
        //        //{
        //        //    secureRandom.NextBytes(iv);
        //        //}

        //        // 4. 配置GCM参数（IV + 认证标签长度128位）
        //        var parameterSpec = new GCMParameterSpec(128, iv);
        //        cipher.Init(CipherMode.EncryptMode, secretKey, parameterSpec);

        //        iv = cipher.GetIV(); // GCM 模式需要 IV
        //        // 5. 加密数据（包含认证标签）
        //        byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(data);
        //        encryptedData = cipher.DoFinal(plaintextBytes);

        //        // 6. 拼接 IV + 密文+标签
        //        byte[] result = new byte[iv.Length + encryptedData.Length];
        //        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        //        Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

        //        // 7. 返回Base64（确保调用方无需日志记录此值）
        //        return Convert.ToBase64String(result);
        //    }
        //    catch (Exception ex)
        //    {
        //        // 记录日志后重新抛出异常，避免静默失败
        //        Console.WriteLine($"加密失败: {ex}");
        //        //throw new InvalidOperationException("数据加密失败", ex);
        //    }
        //    finally
        //    {
        //        // 8. 清理敏感数据内存
        //        if (encryptedData != null)
        //        {
        //            Array.Clear(encryptedData, 0, encryptedData.Length);
        //        }
        //        Array.Clear(iv, 0, iv.Length);
        //    }

        //    return null;
        //}
        //public string? Decrypt(string alias,string data)
        //{
        //    try
        //    {
        //        var keyStore = KeyStore.GetInstance("AndroidKeyStore");
        //        keyStore.Load(null);

        //        //// 获取加密密钥
        //        var secretKey = ((KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null)).SecretKey;
        //        var encryptedDataWithIv = Convert.FromBase64String(data);

        //        // 分离 IV 和加密数据
        //        var iv = new byte[12]; // GCM 模式的 IV 通常为 12 字节
        //        var encryptedData = new byte[encryptedDataWithIv.Length - iv.Length];
        //        Buffer.BlockCopy(encryptedDataWithIv, 0, iv, 0, iv.Length);
        //        Buffer.BlockCopy(encryptedDataWithIv, iv.Length, encryptedData, 0, encryptedData.Length);

        //        // 初始化 Cipher
        //        var cipher = Cipher.GetInstance("AES/GCM/NoPadding");
        //        cipher.Init(CipherMode.DecryptMode, secretKey, new GCMParameterSpec(128, iv)); // GCM 模式需要指定标签长度

        //        // 解密数据
        //        var decryptedData = cipher.DoFinal(encryptedData);
        //        return Encoding.UTF8.GetString(decryptedData);
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine(ex.ToString());
        //    }

        //    return null;
        //}

        public string? Encrypt(string alias, string data)
        {
            byte[] encryptedData = null;
            byte[] iv =null;
            try
            {
                var keyStore = KeyStore.GetInstance("AndroidKeyStore");
                keyStore.Load(null);

                // 如果密钥不存在，则创建
                if (!keyStore.ContainsAlias(alias))
                {
                    var keyGenerator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, "AndroidKeyStore");
                    var keyGenSpec = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                        .SetBlockModes(KeyProperties.BlockModeGcm)
                        .SetKeySize(256)
                        .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                        .SetUserAuthenticationRequired(true) // 必须通过生物认证或设备认证解锁
                        .SetUserAuthenticationValidityDurationSeconds(60) // 可选
                        .Build();

                    keyGenerator.Init(keyGenSpec);
                    keyGenerator.GenerateKey();
                }

                //// 获取加密密钥
                var secretKey = ((KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null)).SecretKey;
                var cipher = Cipher.GetInstance("AES/GCM/NoPadding");
                cipher.Init(CipherMode.EncryptMode, secretKey);

                // 获取 IV 并加密数据
                 iv = cipher.GetIV(); // GCM 模式需要 IV                   // 加密 

                encryptedData = cipher.DoFinal(System.Text.Encoding.UTF8.GetBytes(data));

                // 将 IV 和加密数据一起保存
                var result = new byte[iv.Length + encryptedData.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

                return Convert.ToBase64String(result);
            }
            catch (Exception ex)
            {
                // throw ex;
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                // 8. 清理敏感数据内存
                if (encryptedData != null)
                {
                    Array.Clear(encryptedData, 0, encryptedData.Length);
                }

                if (iv !=null)
                {
                    Array.Clear(iv, 0, iv.Length);
                }
                
            }

            return null;
        }

        public byte[] EncryptByte(string alias, string data)
        {
            byte[] encryptedData = null;
            byte[] iv = null;
            try
            {
                var keyStore = KeyStore.GetInstance("AndroidKeyStore");
                keyStore.Load(null);

                // 如果密钥不存在，则创建
                if (!keyStore.ContainsAlias(alias))
                {
                    var keyGenerator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, "AndroidKeyStore");
                    var keyGenSpec = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                        .SetBlockModes(KeyProperties.BlockModeGcm)
                        .SetKeySize(256)
                        .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                        .SetUserAuthenticationRequired(true) // 必须通过生物认证或设备认证解锁
                        .SetUserAuthenticationValidityDurationSeconds(60) // 可选
                        .Build();

                    keyGenerator.Init(keyGenSpec);
                    keyGenerator.GenerateKey();
                }

                //// 获取加密密钥
                var secretKey = ((KeyStore.SecretKeyEntry)keyStore.GetEntry(alias, null)).SecretKey;
                var cipher = Cipher.GetInstance("AES/GCM/NoPadding");
                cipher.Init(CipherMode.EncryptMode, secretKey);

                // 获取 IV 并加密数据
                iv = cipher.GetIV(); // GCM 模式需要 IV                   // 加密 

                encryptedData = cipher.DoFinal(System.Text.Encoding.UTF8.GetBytes(data));

                // 将 IV 和加密数据一起保存
                var result = new byte[iv.Length + encryptedData.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

                return result;
            }
            catch (Exception ex)
            {
                // throw ex;
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                // 8. 清理敏感数据内存
                if (encryptedData != null)
                {
                    Array.Clear(encryptedData, 0, encryptedData.Length);
                }

                if (iv != null)
                {
                    Array.Clear(iv, 0, iv.Length);
                }

            }

            return null;
        }

        public bool IsBiometricAuthenticationAvailable()
        {
            var authenticators = Build.VERSION.SdkInt >= BuildVersionCodes.R
                   ? AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong | AndroidX.Biometric.BiometricManager.Authenticators.DeviceCredential
                   : AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong; // Android 10 仅支持生物识别

            return biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong) == AndroidX.Biometric.BiometricManager.BiometricSuccess;
        }

        public bool IsLockScreenPasswordSet()
        {
            var keyguardManager = Application.Context.GetSystemService(Context.KeyguardService) as KeyguardManager;
            return keyguardManager.IsKeyguardSecure;
        }
    }
}
