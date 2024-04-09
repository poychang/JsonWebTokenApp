using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JsonWebTokenApp
{
    public class Program
    {
        const string SecureKey = "SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS";

        static void Main(string[] args)
        {
            var token = GenerateToken();
            Console.WriteLine($"Generate JWT: {token}");
            Console.WriteLine($"\n----------\n");

            var isContinue = true;
            while (isContinue)
            {
                Console.WriteLine($"Validate JWT:");
                var checkingToken = Console.ReadLine() ?? string.Empty;
                var result = ValidateToken(checkingToken);
                Console.WriteLine($"Validation Result: {result}");
                Console.WriteLine($"\n----------\n");

                Console.WriteLine($"Continue?");
                isContinue = Console.ReadLine()?.ToLower() is "y";
            }
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
            if (string.IsNullOrEmpty(token)) return false;

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
                var validateResult = handler.ValidateTokenAsync(token, validationParameters).GetAwaiter().GetResult();
                return validateResult.IsValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }
    }
}