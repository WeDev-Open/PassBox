using Microsoft.AspNetCore.Builder;

namespace PassboxApp.Services
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app)
        {
            app.Run(WebApp.OnHttpRequest);
        }
    }
}
