using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JsonWebTokenAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    // When the verification fails, the response header will include the WWW-Authenticate, which displays the detailed for the failure
                    // Sometimes, it will be specifically turned off
                    options.IncludeErrorDetails = true; // default is 'true'

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        // Typically, we would verify the Issuer
                        ValidateIssuer = true,
                        ValidIssuer = "Jwt:Issuer",

                        // Usually, there's not much need to verify the Audience
                        ValidateAudience = false,
                        //ValidAudience = "JwtAuthDemo", // No need to fill out if not verified

                        // Generally, we always verify the validity period of the Token
                        ValidateLifetime = true,

                        // If the token contains a key, it needs to be verified; usually, it only has a signature
                        ValidateIssuerSigningKey = false,

                        // Security key should above 16 characters
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SECURITY_KEY_SHOULD_ABOVE_16_CHARACTERS"))
                    };
                });
            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
