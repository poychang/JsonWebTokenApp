using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;

namespace JsonWebTokenApp
{
    public class Program
    {
        const string SecureKey = "SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS";

        static void Main(string[] args)
        {
            var token = GenerateToken();
            Console.WriteLine($"JWT: {token}");
            Console.WriteLine($"\n----------\n");

            var validation = ValidateToken(token);
            Console.WriteLine($"JWT validation: {validation}");
            Console.WriteLine($"\n----------\n");

            var data = JWTDecoder(token);
            Console.WriteLine($"JWT Decode: {data}");

        }

        static string GenerateToken()
        {
            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://jwt.poychang.net",
                Audience = "https://api.poychang.net",
                Expires = DateTime.UtcNow.AddMinutes(30),
                IssuedAt = DateTime.UtcNow,
                Claims = new Dictionary<string, object> { { "role", "admin" } },
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey)),
                    SecurityAlgorithms.HmacSha256Signature
                ),
            });
            return token;
        }

        static bool ValidateToken(string token)
        {
            var handler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidIssuer = "https://jwt.poychang.net",
                ValidAudience = "https://api.poychang.net",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey)),
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            try
            {
                var claimsPrincipal = handler.ValidateTokenAsync(token, validationParameters);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        static string JWTDecoder(string token)
        {
            var handler = new JsonWebTokenHandler();
            var data = handler.ReadJsonWebToken(token);
            return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}