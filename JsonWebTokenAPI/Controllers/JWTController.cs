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
                return Ok(JwtHelper.GenerateToken(login.Name));
            else
                return BadRequest();

            static bool Validate(LoginModel login) => true;
        }

        // GET /jwt/decode-header
        [Authorize]
        [HttpGet("decode-header")]
        public IActionResult DecodeHeader()
        {
            var handler = new JsonWebTokenHandler();
            var token = HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");
            var jwt = handler.ReadJsonWebToken(token);
            return Ok(Base64UrlEncoder.Decode(jwt.EncodedHeader));
        }
        // GET /jwt/decode-payload
        [Authorize]
        [HttpGet("decode-payload")]
        public IActionResult DecodePayload()
        {
            var handler = new JsonWebTokenHandler();
            var token = HttpContext.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");
            var jwt = handler.ReadJsonWebToken(token);
            return Ok(Base64UrlEncoder.Decode(jwt.EncodedPayload));
        }

        // GET /jwt/role
        [Authorize]
        [HttpGet("role")]
        public IActionResult GetRole()
        {
            var role = HttpContext.User.Claims.Where(claim => claim.Type == ClaimTypes.Role).Select(claim => claim.Value);
            return Ok(role);
        }

        // GET /jwt/claims
        [Authorize(Roles = "admin")]
        [HttpGet("claims")]
        public IActionResult GetClaims()
        {
            var claims = HttpContext.User.Claims.Select(claim => new { claim.Type, claim.Value });
            return Ok(claims);
        }
    }

    public record LoginModel(string Name, string Key);

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
                // In RFC 7519 (Section#4), there are defined 7 built-in Claims
                //new(JwtRegisteredClaimNames.Iss, "issuer"),
                new(JwtRegisteredClaimNames.Sub, name),
                //new(JwtRegisteredClaimNames.Aud, "The Audience"),
                //new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(expireMinutes).ToUnixTimeSeconds().ToString()),
                //new(JwtRegisteredClaimNames.Nbf, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                //new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // JWT ID

                // You can add more registered claims from the list
                // https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.jsonwebtokens.jwtregisteredclaimnames
            };

            // You can define your "roles" to your Claims
            if (name == "admin")
                claims.Add(new Claim(ClaimTypes.Role, "admin"));
            else
                claims.Add(new Claim(ClaimTypes.Role, "user"));
            // You can add custom claims as well
            claims.Add(new Claim("custom", "custom-claim"));

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Create SecurityTokenDescriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = Audience, // Sometimes you don't have to define Audience.
                //NotBefore = DateTime.Now, // Default is DateTime.Now
                //IssuedAt = DateTime.Now, // Default is DateTime.Now
                Subject = new ClaimsIdentity(claims),
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
