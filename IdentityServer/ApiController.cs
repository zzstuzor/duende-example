using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static Duende.IdentityServer.IdentityServerConstants;

namespace IdentityServer;

public sealed class ApiController : ControllerBase
{
    [HttpGet]
    [Route("api/getdata")]
    [Authorize(Policy = LocalApi.PolicyName)]
    [Authorize(Policy = CommonStatics.Policy_IDS)]
    public string GetData() => "success!";
}
