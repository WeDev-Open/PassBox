using Android.Webkit;
using Microsoft.AspNetCore.Components.WebView.Maui;

namespace PassboxApp.Platforms.Android
{
    public class MauiWebChromeClient:WebChromeClient
    {
        public override void OnPermissionRequest(PermissionRequest? request)
        {
            // 处理每个请求
            foreach (var resource in request.GetResources())
            {
                // 检查网页是否正在请求对相机的权限
                if (resource.Equals(PermissionRequest.ResourceVideoCapture, StringComparison.OrdinalIgnoreCase))
                {
                    // 检查网页是否正在请求对相机的权限
                    PermissionStatus status = Permissions.CheckStatusAsync<Permissions.Camera>().Result;

                    // 如果应用程序对摄像头的访问权限未“授予”，则拒绝网页的请求
                    if (status != PermissionStatus.Granted)
                        request.Deny();
                    else
                        request.Grant(request.GetResources());

                    return;
                }
            }
            request.Grant(request.GetResources());
        }
    }

    public class MauiBlazorWebViewHandler : BlazorWebViewHandler
    {
        protected override void ConnectHandler(global::Android.Webkit.WebView platformView)
        {
            platformView.SetWebChromeClient(new MauiWebChromeClient());
            base.ConnectHandler(platformView);
        }
    }
}
