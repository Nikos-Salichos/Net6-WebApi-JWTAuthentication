using JWTAuthenticationWebApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenticationWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static  User user = new User();

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDto) {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

                user.Username = userDto.Username;
                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
                
            return Ok(user);
            
        }


        private void CreatePasswordHash(string password,out byte[]passwordHash , out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }
}
