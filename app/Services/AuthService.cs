using Plugin.Fingerprint;
using Plugin.Fingerprint.Abstractions;

namespace PassboxApp.Services
{
    public class AuthService
    {
        public async Task<bool> AuthenticateAsync(string reason = "Use your fingerprint or device password to authenticate")
        {

            try
            {
                var authenticationRequestConfig = new AuthenticationRequestConfiguration("Authentication Required", reason)
                {
                    AllowAlternativeAuthentication = true, // Enable fallback to PIN/password
                    FallbackTitle = "Use Device Password"  // Optional: Customize the fallback title
                };

                var result = await CrossFingerprint.Current.AuthenticateAsync(authenticationRequestConfig);

                return result.Authenticated;
            }
            catch
            {
                return false;
            }
        }
    }
}
