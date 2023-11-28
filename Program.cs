using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Constants = Microsoft.Identity.Web.Constants;

var builder = WebApplication.CreateBuilder(args);

var initialScopes = builder.Configuration[
    $"{nameof(MicrosoftGraphOptions)}:{nameof(MicrosoftGraphOptions.Scopes)}"
]?.Split(' ');

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOptions();

// Add services to the container.
builder.Services
    .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection(Constants.AzureAdB2C))
    .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
    .AddMicrosoftGraph(builder.Configuration.GetSection(nameof(MicrosoftGraphOptions)))
    .AddDistributedTokenCaches(); //we might need to change this to scale the app

// builder.Services
//     .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//     .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection(Constants.AzureAdB2C))
//     .EnableTokenAcquisitionToCallDownstreamApi()
//     .AddMicrosoftGraph(builder.Configuration.GetSection(nameof(MicrosoftGraphOptions)))
//     .AddInMemoryTokenCaches();

builder.Services.AddSwaggerGen(c => c.SwaggerDoc("v1", new() { Title = "ADB2C", Version = "v1" }));

// .AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
// .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection(Constants.AzureAd))
// .EnableTokenAcquisitionToCallDownstreamApi(initialScopes)
// .AddMicrosoftGraph(builder.Configuration.GetSection(nameof(MicrosoftGraphOptions)))
// .AddDistributedTokenCaches(); //we might need to change this to scale the app

builder.Services.AddMicrosoftGraph();
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
IdentityModelEventSource.LogCompleteSecurityArtifact = true;
IdentityModelEventSource.ShowPII = true;

builder.Services.Configure<CookieAuthenticationOptions>(
    CookieAuthenticationDefaults.AuthenticationScheme,
    options => options.AccessDeniedPath = "/AccessDenied"
);

// builder.Services.Configure<JwtBearerOptions>(
//     JwtBearerDefaults.AuthenticationScheme,
//     options =>
//     {
//         options.Events = new JwtBearerEvents { OnAuthenticationFailed = AuthenticationFailed };
//     }
// );

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});

//if the access to the webapp needs to be limited to a specific role, set the role in the appsettings.json
//if the role is not set, the webapp will be open to all authenticated users
//this allows you to show a friendly access denied message with optional instructions for your users
//how to get access if they want to or if they can
//this access policy is set on the index.html and on the controller through  [Authorize(Policy = "alloweduser")] attribute
var requiredUserRoleForAccess = builder.Configuration["AzureAdB2C:AllowedUsersRole"];
if (!IsNullOrEmpty(requiredUserRoleForAccess))
{
    builder.Services
        .AddAuthorizationBuilder()
        .AddDefaultPolicy(
            "alloweduser",
            policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireRole(requiredUserRoleForAccess);
            }
        );
}
else
{
    builder.Services
        .AddAuthorizationBuilder()
        .AddDefaultPolicy("alloweduser", policy => policy.RequireAuthenticatedUser());
}

builder.Services.Configure<SessionOptions>(
    builder.Configuration.GetSection(nameof(SessionOptions))
);
builder.Services.AddSession();

// options =>
// {
//     options.IdleTimeout = TimeSpan.FromMinutes(1); //You can set Time
//     options.Cookie.IsEssential = true;
//     options.Cookie.SameSite = SameSiteMode.None;
//     options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
//     options.Cookie.HttpOnly = true;
// });

builder.Services.AddRazorPages().AddMicrosoftIdentityUI();

builder.Services.AddHttpClient(); // use iHttpFactory as best practice, should be easy to use extra retry and hold off policies in the future

// The following lines code instruct the asp.net core middleware to use the data in the "roles" claim in the Authorize attribute and User.IsInrole()
// See https://docs.microsoft.com/aspnet/core/security/authorization/roles?view=aspnetcore-2.2 for more info.
builder.Services.Configure<OpenIdConnectOptions>(
    OpenIdConnectDefaults.AuthenticationScheme,
    builder.Configuration.GetSection(nameof(OpenIdConnectOptions))
);

var app = builder.Build();

// this setting is used when you use tools like ngrok or reverse proxies like nginx which connect to http://localhost
// if you don't set this setting the sign-in redirect will be http instead of https
app.UseForwardedHeaders(
    new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedProto }
);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHsts();
    app.UseExceptionHandler("/Error");
}

app.UseSession();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseCookiePolicy(new CookiePolicyOptions { Secure = CookieSecurePolicy.Always });

app.MapRazorPages();
app.MapControllers();

// generate an api-key on startup that we can use to validate callbacks
env.SetEnvironmentVariable("API-KEY", guid.NewGuid().ToString());

app.Run();
