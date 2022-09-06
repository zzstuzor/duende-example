using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer;

public sealed class ApiController : ControllerBase
{
    [HttpGet]
    [Route("api/getdata")]
    [Authorize(Policy = CommonStatics.Policy_IDS)]
    public string GetData() => "success!";
}
