using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JsonWebTokenApp
{
    public class Program
    {
        const string Issuer = "Jwt:Issuer";
        const string Audience = "Jwt:Audience";
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
            }
        }

        static string GenerateToken()
        {
            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Issuer,
                Audience = Audience,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(1),
                Claims = new Dictionary<string, object> { { "role", "user" } },
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey)),
                    SecurityAlgorithms.HmacSha256
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
                ValidIssuer = Issuer,
                ValidAudience = Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecureKey)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
            };
            try
            {
                var validateResult = handler.ValidateTokenAsync(token, validationParameters).GetAwaiter().GetResult();
                Console.WriteLine(validateResult.Exception?.Message);
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