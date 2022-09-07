using Common;
using Common.filters;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using Serilog;

namespace IdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder
            .Services
            .AddHttpContextAccessor()
            .AddDbContext<MyDbContext>(options => options.UseInMemoryDatabase("id-db"))
            .AddIdentity<IdentityUser, IdentityRole>()
            .AddTokenProvider<DataProtectorTokenProvider<IdentityUser>>(TokenOptions.DefaultProvider)
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<MyDbContext>()
            .AddSignInManager<SignInManager<IdentityUser>>()
            //.AddUserManager<UserManager<IdentityUser>>()
            .AddClaimsPrincipalFactory<MyClaimsPrincipalFactory>()
            .Services
            .AddLocalApiAuthentication()
            .AddRazorPages();

        // Add authentication
        const string AUTH_SCHEME = "JWT_OR_COOKIE";
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
                        // etc
                    };
                })
            .AddCookie(CommonStatics.Cookie)
            .AddPolicyScheme(AUTH_SCHEME, AUTH_SCHEME,
                options =>
                {
                    options.ForwardDefaultSelector =
                        context =>
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
                options.AddPolicy(CommonStatics.Policy_IDS,
                    policy =>
                    {
                        policy.RequireAuthenticatedUser();
                        policy.RequireClaim("scope", CommonStatics.Scope_IDS);
                    });
            });

        builder.Services
            .AddIdentityServer(
                options =>
                {
                    // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
                    options.EmitStaticAudienceClaim = true;
                })
            .AddProfileService<ProfileService>()
            .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddTestUsers(TestUsers.Users);

        builder.Services
            .ConfigureApplicationCookie(config =>
            {
                config.Cookie.Name = CommonStatics.Cookie;
                config.LoginPath = "/Account/Login";
                config.LogoutPath = "/Account/Logout";
            })
            .AddCors(options =>
            {
                options.AddDefaultPolicy(builder => builder
                    .WithOrigins(new string[] { CommonStatics.URL_MyApi, CommonStatics.URL_Identity })
                    .AllowAnyHeader());
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
                Title = "Identity Server API",
                Version = "1.0",
                License = new OpenApiLicense()
            });

            var scopes = new Dictionary<string, string>
            {
                { CommonStatics.Scope_IDS, "Identity API" }
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
                    Description = "Identity Server API",
                });
        });

        builder.Services.AddControllers();

        return builder.Build();
    }
    
    public static WebApplication ConfigurePipeline(this WebApplication app)
    { 
        app.UseSerilogRequestLogging();
    
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseCors();

        app.UseAuthentication();
        app.UseIdentityServer();
        app.UseJwtTokenMiddleware();
        app.UseAuthorization();

        var redirectUrl = new Uri(new Uri(CommonStatics.URL_Identity), "swagger/oauth2-redirect.html");
        app.UseSwagger();
        app.UseSwaggerUI(setup =>
        {
            setup.OAuth2RedirectUrl(redirectUrl.ToString());
            setup.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Server API");
            setup.OAuthClientId(CommonStatics.Client_Swagger);
            setup.OAuthAppName("IdentityServerAPI");
            setup.OAuthScopeSeparator(" ");
            setup.OAuthClientSecret(CommonStatics.Secret_Swagger);
            setup.OAuthScopes($"{CommonStatics.Scope_IDS}");
            setup.OAuthUsePkce();
        });

        app.MapRazorPages();

        app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());

        return app;
    }
}
