﻿using Microsoft.AspNetCore.Http;
using System.Text;

namespace PassboxApp.Services
{
    public class WebApp
    {
        private static readonly byte[] _helloWorldBytes = Encoding.UTF8.GetBytes(
            "Hello Xamarin, greetings from Kestrel");

        public static Task OnHttpRequest(HttpContext httpContext)
        {
            var response = httpContext.Response;
            response.StatusCode = 200;
            response.ContentType = "text/plain";

            var helloWorld = _helloWorldBytes;
            response.ContentLength = helloWorld.Length;
            return response.Body.WriteAsync(helloWorld, 0, helloWorld.Length);
        }
    }
}
