using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityServer;

public sealed class ProfileService : IProfileService
{
    readonly UserManager<IdentityUser> _userManager;
    readonly IUserClaimsPrincipalFactory<IdentityUser> _claimsFactory;
    readonly ILogger<ProfileService> _logger;

    public ProfileService(
        UserManager<IdentityUser> userManager,
        IUserClaimsPrincipalFactory<IdentityUser> claimsFactory,
        ILogger<ProfileService> logger)
    {
        _userManager = userManager;
        _claimsFactory = claimsFactory;
        _logger = logger;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var sub = context.Subject.GetSubjectId();
        var user = await _userManager.FindByIdAsync(sub);
        var principal = await _claimsFactory.CreateAsync(user);
        var claims = principal.Claims.ToList();
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            context.IssuedClaims.Add(new Claim(JwtClaimTypes.Role, role));
        }
        context.IssuedClaims.AddRange(claims);
        _logger.LogInformation("GetProfileDataAsync:" + string.Join(';', context.IssuedClaims.Select(c => $"[{c.Type}:{c.Value}]")));
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        var user = await _userManager.FindByIdAsync(context.Subject.Identity.GetSubjectId());
        context.IsActive = (user != null);
    }
}
