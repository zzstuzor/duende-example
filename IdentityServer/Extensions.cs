using Microsoft.AspNetCore.Authentication;
using System.Security.Principal;

namespace IdentityServer;

public static class MiddlewareExtensions
{
    /// <summary>
    /// This helps for API callers who have a token but aren't authenticated somehow. Magic
    /// Taken from: https://stackoverflow.com/a/53921825/1414258
    /// </summary>
    public static IApplicationBuilder UseJwtTokenMiddleware(this IApplicationBuilder app,
        string schema = "Bearer")
    {
        return app.Use((async (ctx, next) =>
        {
            IIdentity identity = ctx.User?.Identity;
            if (identity != null && !identity.IsAuthenticated)
            {
                AuthenticateResult authenticateResult = await ctx.AuthenticateAsync(schema);
                if (authenticateResult.Succeeded && authenticateResult.Principal != null)
                    ctx.User = authenticateResult.Principal;
            }
            await next();
        }));
    }
}
