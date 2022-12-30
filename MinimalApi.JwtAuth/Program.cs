using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();
builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "Minimal API - JWT Authentication",
        Description = "Implementing JWT Authentication in Minimal API",
        TermsOfService = new Uri("http://www.example.com"),
    });

    var securityScheme = new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Name = JwtBearerDefaults.AuthenticationScheme,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        Reference = new()
        {
            Type = ReferenceType.SecurityScheme,
            Id = JwtBearerDefaults.AuthenticationScheme
        }
    };

    options.AddSecurityDefinition("Bearer", securityScheme);

    options.AddSecurityRequirement(new()
    {
        [securityScheme] = new List<string>()
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.MapPost("/token", (
    LoginDto loginDto,
    IAuthenticationConfigurationProvider authenticationConfigurationProvider) =>
{
    // Add this code to a TokenService class
    var bearerSection = authenticationConfigurationProvider.GetSchemeConfiguration(
        JwtBearerDefaults.AuthenticationScheme);

    var section = bearerSection.GetSection("SigningKeys:0");

    var issuer = bearerSection["ValidIssuer"] ?? throw new InvalidOperationException("Issuer is not specified");
    var signingKeyBase64 = section["Value"] ?? throw new InvalidOperationException("Signing Key is not specified");

    var signinKeyBytes = Convert.FromBase64String(signingKeyBase64);

    var jwtSigningCredentials = new SigningCredentials(
        new SymmetricSecurityKey(signinKeyBytes),
        SecurityAlgorithms.HmacSha256Signature);

    var audiences = bearerSection.GetSection("ValidAudiences").GetChildren()
        .Where(s => !string.IsNullOrEmpty(s.Value))
        .Select(s => new Claim(JwtRegisteredClaimNames.Aud, s.Value!))
        .ToArray();

    var identity = new ClaimsIdentity(JwtBearerDefaults.AuthenticationScheme);
    identity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, loginDto.Username));

    identity.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
    identity.AddClaims(audiences);

    var handler = new JwtSecurityTokenHandler();

    var token = handler.CreateJwtSecurityToken(
        issuer,
        audience: null,
        identity,
        notBefore: DateTime.UtcNow,
        expires: DateTime.UtcNow.AddDays(1),
        issuedAt: DateTime.UtcNow,
        jwtSigningCredentials);

    return Results.Ok(
        new
        {
            Token = handler.WriteToken(token)
        });
})
.AllowAnonymous()
.WithName("Token")
.WithOpenApi();

app.MapGet("/private", () =>
{
    return Results.Ok("authenticated");
})
.RequireAuthorization()
.WithName("Private")
.WithOpenApi();

app.Run();

public record LoginDto(string Username, string Password);
