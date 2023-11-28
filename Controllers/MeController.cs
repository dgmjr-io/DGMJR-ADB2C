namespace ADB2C.Controllers;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web.Resource;
using Microsoft.Identity.Web;
using Microsoft.Graph;

[Authorize(Policy = "alloweduser")]
[ApiController]
public class MeController(GraphServiceClient graphClient) : ControllerBase
{
    private readonly GraphServiceClient _graphClient = graphClient;

    [HttpGet]
    [Route("api/me")]
    [AuthorizeForScopes(ScopeKeySection = "AzureAdB2C:Scopes")]
    public async Task<User> Get()
    {
        var graphUser = await _graphClient.Me
            .Request()
            // .Select(
            //     u =>
            //         new
            //         {
            //             u.AboutMe,
            //             u.AgeGroup,
            //             u.AdditionalData,
            //             u.Activities,
            //             u.City,
            //             u.Interests,
            //             u.Identities
            //         }
            // )
            .GetAsync();
        return graphUser;
    }

    [HttpPut]
    [Route("api/me")]
    [AuthorizeForScopes(ScopeKeySection = "AzureAdB2C:Scopes")]
    public async Task<User> Set([FromBody] System.Security.Claims.Claim claim)
    {
        var graphUser = await _graphClient.Me
            .Request()
            .UpdateAsync(
                new User
                {
                    AdditionalData = new Dictionary<string, object> { { claim.Type, claim.Value } }
                }
            );
        return graphUser;
    }
}
