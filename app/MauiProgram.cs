using Microsoft.AspNetCore.Components.WebView.Maui;
using Microsoft.Extensions.Logging;
using PassboxApp.Platforms.Android;
using PassboxApp.Services;

namespace PassboxApp
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                });

            builder.Services.AddMauiBlazorWebView();
            builder.Services.AddSingleton<ISecurityService, SecurityService>();
            builder.Services.AddSingleton<INetworkService, NetworkService>();
            builder.Services.AddSingleton<PasswordDatabaseService>();
            builder.Services.AddSingleton<PasswordGenerator>();
            builder.Services.AddSingleton<SSEServerService>();

            builder.Services.AddMasaBlazor();

#if ANDROID
            builder.ConfigureMauiHandlers(handlers =>
            {
                handlers.AddHandler<IBlazorWebView, MauiBlazorWebViewHandler>();
            });
#endif

#if DEBUG
            builder.Services.AddBlazorWebViewDeveloperTools();
    		builder.Logging.AddDebug();
#endif

            return builder.Build();
        }
    }
}
