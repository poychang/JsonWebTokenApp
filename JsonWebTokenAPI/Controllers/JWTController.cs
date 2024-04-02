using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Security.Claims;
using System.Text;

namespace JsonWebTokenAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JWTController : ControllerBase
    {
        // POST /jwt/login
        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Get(LoginModel login)
        {
            if (Validate(login))
            {
                var expireMinutes = 10;
                return Ok(new
                {
                    App = login.Name,
                    Token = JwtHelper.GenerateToken(login.Name, expireMinutes),
                    Create = DateTime.Now,
                    Expire = DateTime.Now.AddMinutes(expireMinutes),
                });
            }
            else
            {
                return BadRequest();
            }

            static bool Validate(LoginModel login) => true;
        }

        // GET /jwt/decode
        [Authorize]
        [HttpGet("decode")]
        public IActionResult Decode()
        {
            var handler = new JsonWebTokenHandler();
            var token = HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");
            var data = handler.ReadJsonWebToken(token);
            return Ok(data);
        }

        // GET /jwt/claims
        [Authorize]
        [HttpGet("claims")]
        public IActionResult GetClaims()
        {
            var claims = HttpContext.User.Claims.Select(claim => new { claim.Type, claim.Value });
            return Ok(claims);
        }

        // GET /jwt/role
        [Authorize(Roles = "admins")]
        [HttpGet("role")]
        public IActionResult GetRole()
        {
            var role = HttpContext.User.Claims.Where(claim => claim.Type == JwtRegisteredClaimNames.Sub).Select(claim => claim.Value);
            return Ok(role);
        }
    }

    public record LoginModel(string Name, string Key);

    public static class JwtHelper
    {
        const string Issuer = "Jwt:Issuer";
        const string SecureKey = "SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS";
        public static string GenerateToken(string userName, int expireMinutes = 10)
        {
            // Configuring "Claims" to your JWT Token
            var claims = new List<Claim>
            {
                // In RFC 7519 (Section#4), there are defined 7 built-in Claims, but we mostly use 2 of them
                //new(JwtRegisteredClaimNames.Iss, "issuer"),
                new(JwtRegisteredClaimNames.Sub, userName), // User.Identity.Name
                //new(JwtRegisteredClaimNames.Aud, "The Audience"),
                //new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(expireMinutes).ToUnixTimeSeconds().ToString()),
                //new(JwtRegisteredClaimNames.Nbf, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                //new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID

                // You can add more registered claims from the list
                // https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.jsonwebtokens.jwtregisteredclaimnames
            };

            // You can define your "roles" to your Claims
            claims.Add(new Claim(ClaimTypes.Role, "admin"));
            claims.Add(new Claim(ClaimTypes.Role, "users"));
            // You can add custom claims as well
            claims.Add(new Claim("custom", "claim"));

            var claimsIdentity = new ClaimsIdentity(claims);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Create SecurityTokenDescriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                //Audience = issuer, // Sometimes you don't have to define Audience.
                //NotBefore = DateTime.Now, // Default is DateTime.Now
                //IssuedAt = DateTime.Now, // Default is DateTime.Now
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
}
