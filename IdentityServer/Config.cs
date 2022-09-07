using Common;
using Duende.IdentityServer.Models;
using static Duende.IdentityServer.IdentityServerConstants;

namespace IdentityServer;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        { 
            new IdentityResources.OpenId()
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
            {
                new ApiScope(CommonStatics.Scope_IDS, "Identity API"),
                new ApiScope(CommonStatics.Scope_MyApi, "My API"),
                new ApiScope(LocalApi.ScopeName, "Duende Local API"),
            };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            new Client
            {
                ClientId = CommonStatics.Client_Swagger,
                ClientSecrets = { new Secret(CommonStatics.Secret_Swagger.Sha256()) },
                AllowedGrantTypes = { "authorization_code" },
                AllowedScopes = { CommonStatics.Scope_IDS, CommonStatics.Scope_MyApi, LocalApi.ScopeName },
                AlwaysIncludeUserClaimsInIdToken = true,
                AlwaysSendClientClaims = true,
                AccessTokenLifetime = 1800,
                AllowOfflineAccess = false,
                AccessTokenType = AccessTokenType.Jwt,
                RedirectUris =
                {
                    new Uri(new Uri(CommonStatics.URL_Identity), "swagger/oauth2-redirect.html").ToString(),
                    new Uri(new Uri(CommonStatics.URL_MyApi), "swagger/oauth2-redirect.html").ToString(),
                },
                PostLogoutRedirectUris =
                {
                    new Uri(new Uri(CommonStatics.URL_Identity), "swagger/index.html").ToString(),
                    new Uri(new Uri(CommonStatics.URL_MyApi), "swagger/index.html").ToString(),
                },
                AllowedCorsOrigins = { CommonStatics.URL_Identity, CommonStatics.URL_MyApi },
            },
            new Client
            {
                ClientId = CommonStatics.Client_DesktopClient,
                ClientSecrets = { new Secret(CommonStatics.Secret_DesktopClient.Sha256()) },
                AllowedGrantTypes = { "password" },
                AllowedScopes = { CommonStatics.Scope_MyApi },
                AlwaysIncludeUserClaimsInIdToken = true,
                AlwaysSendClientClaims = true,
                AccessTokenLifetime = 1800,
                AllowOfflineAccess = false,
                AccessTokenType = AccessTokenType.Jwt,
                AbsoluteRefreshTokenLifetime = 0,
                SlidingRefreshTokenLifetime = 7776000,
                RefreshTokenExpiration = TokenExpiration.Sliding,
                RefreshTokenUsage = TokenUsage.ReUse,
            }
        };
}