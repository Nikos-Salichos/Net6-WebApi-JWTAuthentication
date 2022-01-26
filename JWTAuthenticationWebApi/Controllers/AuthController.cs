using JWTAuthenticationWebApi.Models;
using JWTAuthenticationWebApi.Services.UserService;
using Microsoft.AspNetCore.Authorization;
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
        public static new User User { get; set; } = new();
        private readonly IUserService _userService;


        public AuthController(IConfiguration configuration, IUserService userService)
        {
            this.configuration = configuration;
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            User.Username = userDto.Username;
            User.PasswordHash = passwordHash;
            User.PasswordSalt = passwordSalt;

            return Ok(User);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto userDto)
        {
            if (User.Username != userDto.Username)
            {
                return BadRequest("Wrong Username");
            }


            if (!VerifyPasswordHash(userDto.Password, User.PasswordHash, User.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            string token = CreateToken(User);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
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

        [HttpGet("GetUsername"), Authorize]
        public ActionResult<string> GetUsername()
        {
            var userName = _userService.GetMyName();
            return Ok(userName);
        }

        [HttpGet("GetUsernameAdmin"), Authorize(Roles = "Admin")]
        public string GetAdmin()
        {
            User admin = new User
            {
                Username = "Nikos"
            };

            return admin.Username;
        }
    }
}
