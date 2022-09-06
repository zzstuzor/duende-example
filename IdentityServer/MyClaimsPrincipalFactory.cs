using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace IdentityServer;

public sealed class MyClaimsPrincipalFactory :
    UserClaimsPrincipalFactory<IdentityUser, IdentityRole>
{
    public MyClaimsPrincipalFactory(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> options)
        : base(userManager, roleManager, options)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdentityUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        if (!identity.HasClaim(x => x.Type == JwtClaimTypes.Subject))
            identity.AddClaim(new Claim(JwtClaimTypes.Subject, user.Id));
        return identity;
    }
}
