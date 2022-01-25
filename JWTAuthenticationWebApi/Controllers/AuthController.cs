using JWTAuthenticationWebApi.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenticationWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;

        public static User User1 { get; set; } = new();

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            User1.Username = userDto.Username;
            User1.PasswordHash = passwordHash;
            User1.PasswordSalt = passwordSalt;

            return Ok(User1);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto userDto)
        {
            if (User1.Username != userDto.Username)
            {
                return BadRequest("Wrong Username");
            }


            if (!VerifyPasswordHash(userDto.Password, User1.PasswordHash, User1.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            string token = CreateToken(User1);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.Username),
            };

            SymmetricSecurityKey? key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("AppSettings:Token").Value));

            SigningCredentials? credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            JwtSecurityToken? token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: credentials);

            string? jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }


        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computerHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computerHash.SequenceEqual(passwordHash);
            }
        }

    }
}
