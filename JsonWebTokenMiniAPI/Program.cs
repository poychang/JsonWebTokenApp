#region STEP 0: Install NuGet package Microsoft.AspNetCore.Authentication.JwtBearer
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
#endregion
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
#region STEP 2: Add Authentication service to DI container
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Typically, we would verify the Issuer
            ValidIssuer = JwtHelper.Issuer,
            ValidAudience = JwtHelper.Audience,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtHelper.SecureKey))
        };
    });
builder.Services.AddAuthorization();
#endregion

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();
#region STEP 3: Add Authentication and Authorization middleware
app.UseAuthentication();
app.UseAuthorization();
#endregion

#region STEP 4: Add JWT API
app.MapPost("/jwt/login", (LoginModel login) =>
{
    var expireMinutes = 10;

    if (Validate(login))
        return Results.Text(JwtHelper.GenerateToken(login.Name, expireMinutes));
    else
        return Results.BadRequest();

    static bool Validate(LoginModel login) => true;
});

app.MapGet("/jwt/decode-payload", (HttpContext context) =>
{
    var handler = new JsonWebTokenHandler();
    var token = context.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");
    var jwt = handler.ReadJsonWebToken(token);
    return Results.Text(Base64UrlEncoder.Decode(jwt.EncodedPayload));
});
app.MapGet("/jwt/decode-header", (HttpContext context) =>
{
    var handler = new JsonWebTokenHandler();
    var token = context.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");
    var jwt = handler.ReadJsonWebToken(token);
    return Results.Text(Base64UrlEncoder.Decode(jwt.EncodedHeader));
});
app.MapGet("/jwt/anyone", () => Results.Ok("hi anyone"));
app.MapGet("/jwt/user", () => Results.Ok("hi user")).RequireAuthorization();
#endregion

app.Run();

public record LoginModel(string Name, string Key);

#region STEP 1: Add JwtHelper to generate JWT Token
public static class JwtHelper
{
    public static string Issuer = "Jwt:Issuer";
    public static string Audience = "Jwt:Audience";
    public static string SecureKey = "SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS";

    public static string GenerateToken(string name, int expireMinutes = 1)
    {
        // Configuring "Claims" to your JWT Token
        var claims = new List<Claim>
        {
            // Standard claims in RFC 7519
            new(JwtRegisteredClaimNames.Iss, Issuer),
            new(JwtRegisteredClaimNames.Sub, name),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // You can add custom claims as well
            new Claim("custom", "custom-claim"),
        };
        var claimsIdentity = new ClaimsIdentity(claims);
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Create SecurityTokenDescriptor
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            Subject = claimsIdentity,
            Expires = DateTime.Now.AddMinutes(expireMinutes),
            SigningCredentials = credentials
        };

        // Generate a JWT
        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);

        return token;
    }
}
#endregion