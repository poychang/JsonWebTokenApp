using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JsonWebTokenApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://jwt.poychang.net",
                Audience = "https://api.poychang.net",
                Expires = DateTime.UtcNow.AddMinutes(30),
                IssuedAt = DateTime.UtcNow,
                Claims = new Dictionary<string, object> { { "", "" } },
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS")),
                    SecurityAlgorithms.HmacSha256Signature
                ),
            });

            Console.WriteLine($"Token: {token}");
        }
    }
}