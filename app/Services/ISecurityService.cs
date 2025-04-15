using PassboxApp.Platforms.Android;

namespace PassboxApp.Services
{
    public interface ISecurityService
    {
        bool IsBiometricAuthenticationAvailable();
        bool IsLockScreenPasswordSet();

        Task<CallbackResult> AuthenticateAsync(string reson= "Please fingerprint or enter device password", bool isAllowAlternativeAuthentication = true);

        string? Encrypt(string alias, string data);

        string? Decrypt(string alias, string data);

        byte[]? EncryptByte(string alias, string data);

        byte[]? DecryptByte(string alias, string data);
    }
}
