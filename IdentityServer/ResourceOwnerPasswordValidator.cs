using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer;

public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
{
    readonly UserManager<IdentityUser> _userManager;
    public ResourceOwnerPasswordValidator(UserManager<IdentityUser> userManager) =>
        _userManager = userManager;

    GrantValidationResult _getInvalid() =>
        new GrantValidationResult(TokenRequestErrors.InvalidGrant, "invalid credentials");

    public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
    {
        try
        {
            //if (!context.UserName.IsValidEmailAddress())
            //{
            //    context.Result = _getInvalid();
            //    return;
            //}

            var email = context.UserName;//.NormalizeEmail();
            var user = _userManager.Users
                .FirstOrDefault(u => u.NormalizedUserName == email);
            if (user != null &&
                await _userManager.CheckPasswordAsync(user, context.Password))
            {
                context.Result = new GrantValidationResult(user.Id, "password");
                return;
            }
        }
        catch { /*swallow*/ }

        context.Result = _getInvalid();
    }
}
