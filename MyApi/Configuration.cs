using Common;
using Common.filters;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;

namespace MyApi;

public static class Configuration
{
    const string AUTH_SCHEME = "JWT_OR_COOKIE";

    public static WebApplicationBuilder ConfigureMyServices(this WebApplicationBuilder builder)
    {
        builder.Services
            .AddAuthentication(
                options =>
                {
                    options.DefaultScheme = AUTH_SCHEME;
                    options.DefaultChallengeScheme = AUTH_SCHEME;
                })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
                options =>
                {
                    options.Authority = CommonStatics.URL_Identity;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = CommonStatics.URL_Identity,

                        ValidateAudience = false,
                    };
                })
            .AddCookie(CommonStatics.Cookie)
            .AddPolicyScheme(AUTH_SCHEME, AUTH_SCHEME,
                options =>
                {
                    options.ForwardDefaultSelector = context =>
                    {
                        string auth = context.Request.Headers[HeaderNames.Authorization];
                        if (!string.IsNullOrEmpty(auth) && auth.StartsWith(JwtBearerDefaults.AuthenticationScheme))
                            return JwtBearerDefaults.AuthenticationScheme;
                        return CommonStatics.Cookie;
                    };
                });
        builder.Services.AddAuthorization(
            options =>
            {
                options.AddPolicy(CommonStatics.Policy_MyApi,
                    policy =>
                    {
                        policy.RequireAuthenticatedUser();
                        policy.RequireClaim("scope", CommonStatics.Scope_MyApi);
                    });
            });

        // Add swagger
        var authBase = new Uri(CommonStatics.URL_Identity);
        var authUrl = new Uri(authBase, "connect/authorize");
        var tokenUrl = new Uri(authBase, "connect/token");
        builder.Services.AddSwaggerGen(options =>
        {
            options.OperationFilter<AuthorizeOperationFilter>();
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "My API",
                Version = "1.0",
                License = new OpenApiLicense()
            });

            var scopes = new Dictionary<string, string>
            {
                { CommonStatics.Scope_IDS, "Identity API" },
                { CommonStatics.Scope_MyApi, "My API" }
            };
            options.AddSecurityDefinition("OAuth2",
                new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        AuthorizationCode = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = authUrl,
                            TokenUrl = tokenUrl,
                            Scopes = scopes,
                            RefreshUrl = tokenUrl,
                        }
                    },
                    Description = "My API",
                });
        });

        builder.Services.AddControllers();

        return builder;
    }

    public static WebApplication ConfigureMyApp(this WebApplication app)
    {
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        var redirectUrl = new Uri(new Uri(CommonStatics.URL_MyApi), "swagger/oauth2-redirect.html");
        app.UseSwagger();
        app.UseSwaggerUI(setup =>
        {
            setup.OAuth2RedirectUrl(redirectUrl.ToString());
            setup.SwaggerEndpoint("/swagger/v1/swagger.json", "My API");
            setup.OAuthClientId(CommonStatics.Client_Swagger);
            setup.OAuthAppName("MyAPI");
            setup.OAuthScopeSeparator(" ");
            setup.OAuthClientSecret(CommonStatics.Secret_Swagger);
            setup.OAuthScopes($"{CommonStatics.Scope_IDS} {CommonStatics.Scope_MyApi}");
            setup.OAuthUsePkce();
        });

        app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());

        return app;
    }
}
