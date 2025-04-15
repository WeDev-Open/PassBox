using Android;
using Android.App;
using Android.Content.PM;
using Android.OS;
using AndroidX.Core.App;
using Plugin.Fingerprint;

namespace PassboxApp
{
    [Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
    public class MainActivity : MauiAppCompatActivity
    {
        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            // Set the resolver for the current activity
            CrossFingerprint.SetCurrentActivityResolver(() => this);
            ActivityCompat.RequestPermissions(this, [Manifest.Permission.Camera], 0);
            // GlobalData.DirPath= System.Environment.GetFolderPath(System.Environment.SpecialFolder.Personal);
        }
    }
}
