using System.Security.Cryptography;
using System.Text;

namespace PassboxApp.Services
{
    public class PasswordGenerator
    {
        /// <summary>
        /// 生成 HMAC 密钥
        /// </summary>
        /// <param name="keySize">密钥长度（字节）</param>
        /// <returns>HMAC 密钥的字节数组</returns>
        public static byte[] GenerateHmacKey(int keySize = 32)
        {
            // 参数校验
            if (keySize <= 0)
                throw new ArgumentOutOfRangeException(nameof(keySize), "密钥长度必须为正整数");

            // 生成随机密钥
            byte[] key = new byte[keySize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        /// <summary>
        /// 生成随机盐值
        /// </summary>
        /// <param name="size">盐值长度，默认为 32 字节</param>
        /// <returns>盐值的字节数组</returns>
        private static byte[] GenerateSalt(int size = 32)
        {
            try
            {// 参数校验
                if (size <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(size), "盐值长度必须为正整数。");
                }
                using var rng = RandomNumberGenerator.Create();
                var salt = new byte[size];
                rng.GetBytes(salt);
                return salt;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                // 记录日志（示例）
                //Logger.LogError(ex, "盐值长度参数无效。");
                throw new CryptographicException("盐值长度配置错误。", ex);
            }
            catch (CryptographicException ex)
            {
                //Logger.LogError(ex, "加密服务异常，可能因系统环境导致。");
                throw ex;
            }
            catch (Exception ex)
            {
                //Logger.LogError(ex, "生成盐值时发生未知错误。");
                throw new CryptographicException("生成盐值失败，请检查随机数生成器。", ex);
            }
        }

        /// <summary>
        /// 生成随机盐值（Base64 编码）
        /// </summary>
        /// <param name="size">盐值长度，默认为 32 字节</param>
        /// <returns>Base64 编码的盐值字符串</returns>
        public static string GenerateSaltBase64(int size = 32)
        {
            var saltBytes = GenerateSalt(size);
            return Convert.ToBase64String(saltBytes);
        }


        public static string GeneratePassword(string lockScreenKey, string salt, int passwordLength = 32, bool includeSpecialChars = true)
        {
            if (passwordLength < 16)
                throw new ArgumentException("Password length must be at least 16 to include all character types.");

            // 使用 PBKDF2 生成初始密钥
            var pbkdf2 = new Rfc2898DeriveBytes(lockScreenKey, Encoding.UTF8.GetBytes(salt), 50000, HashAlgorithmName.SHA512);
            byte[] initialKey = pbkdf2.GetBytes(passwordLength);

            // 定义字符集
            string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string numberChars = "0123456789";
            string specialChars = "!@#$%^&*()_-+=[]{}|;:,.<>?";

            var validChars = lowercaseChars + uppercaseChars + numberChars;
            if (includeSpecialChars) validChars += specialChars;

            // 初始化密码，确保包含每种类型的字符
            var password = new StringBuilder();
            using (var rng = RandomNumberGenerator.Create())
            {
                // 保证每种字符类型至少包含一个
                password.Append(lowercaseChars[RandomNumberGenerator.GetInt32(lowercaseChars.Length)]);
                password.Append(uppercaseChars[RandomNumberGenerator.GetInt32(uppercaseChars.Length)]);
                password.Append(numberChars[RandomNumberGenerator.GetInt32(numberChars.Length)]);
                if (includeSpecialChars)
                    password.Append(specialChars[RandomNumberGenerator.GetInt32(specialChars.Length)]);

                // 填充剩余字符
                for (int i = password.Length; i < passwordLength; i++)
                {
                    password.Append(validChars[RandomNumberGenerator.GetInt32(validChars.Length)]);
                }
            }

            // 随机打乱字符顺序
            return ShuffleString(password.ToString());
        }

        // 洗牌算法
        private static string ShuffleString(string input)
        {
            var array = input.ToCharArray();
            using (var rng = RandomNumberGenerator.Create())
            {
                for (int i = array.Length - 1; i > 0; i--)
                {
                    byte[] buffer = new byte[4];
                    rng.GetBytes(buffer);
                    int j = BitConverter.ToInt32(buffer, 0) & 0x7FFFFFFF % (i + 1);
                    (array[i], array[j]) = (array[j], array[i]);
                }
            }
            return new string(array);
        }


    }
}
