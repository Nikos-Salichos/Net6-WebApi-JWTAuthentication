using JWTAuthenticationWebApi.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenticationWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static User user = new User();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto)
        {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = userDto.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto userDto)
        {
            if (user.Username != userDto.Username)
            {
                return BadRequest("Wrong Username");
            }


            if (!VerifyPasswordHash(userDto.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }

            return Ok("Login Successful");
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
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computerHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computerHash.SequenceEqual(passwordHash);
            };


        }

    }
}
