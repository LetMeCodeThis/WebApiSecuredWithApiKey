using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace WebApiSecuredWithApiKey.Attributes
{
    public class ApiKeySetup
    {
        public const string FrontendClientApiKey = "AppSettings:ApiKeys:FrontendClient";
    }

    public class ApiKeyAuthorization : Attribute, IAuthorizationFilter
    {
        internal const string XApiHeaderKey = "X-Api-Key";

        public string[] AllowedFor { get; set; }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var hostEnv = context.HttpContext.RequestServices.GetRequiredService<IHostEnvironment>();

            if (!context.HttpContext.Request.Headers.TryGetValue(XApiHeaderKey, out var headerValue))
            {
                var message = hostEnv.IsDevelopment()
                    ? $"Missing header: {XApiHeaderKey}"
                    : "User not authorized";

                context.Result = new UnauthorizedObjectResult(message);

                return;
            }
            
            var config = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();

            foreach (var allowedApiKey in AllowedFor)
            {
                var configuredApiKey = config.GetValue<string>(allowedApiKey);

                if (!string.IsNullOrEmpty(configuredApiKey) && configuredApiKey == headerValue)
                {
                    return;
                }
            }

            var msg = hostEnv.IsDevelopment()
                ? $"Invalid value of header: {XApiHeaderKey}"
                : "User not authorized";

            context.Result = new UnauthorizedObjectResult(msg);
        }
    }
}