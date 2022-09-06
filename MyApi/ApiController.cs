using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MyApi;

public sealed class ApiController : ControllerBase
{
    [HttpGet]
    [Route("api/getstuff")]
    [Authorize(Policy = CommonStatics.Policy_MyApi)]
    public string GetMyApiStuff() => "myApi success!";
}
