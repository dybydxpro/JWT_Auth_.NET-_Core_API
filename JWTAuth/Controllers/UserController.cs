using JWTAuth.Data;
using JWTAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        public readonly AppDatabaseContext _db;
        public readonly IConfiguration _configuration;

        public UserController(AppDatabaseContext db, IConfiguration configuration)
        {
            _db = db;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserRegister userRegister)
        {
            User user = new User();
            CreatePasswordHash(userRegister.Password, out byte[] passwordHash, out byte[] passwordSalt);

            List<User> users = _db.Users.Where(x => x.Email == user.Email).ToList();
            if (users.Count > 0)
            {
                return BadRequest("Email already used!");
            }
            else
            {
                if (ModelState.IsValid)
                {
                    user.Name = userRegister.Name;
                    user.Email = userRegister.Email;
                    user.PasswordHash = passwordHash;
                    user.PasswordSalt = passwordSalt;

                    await _db.Users.AddAsync(user);
                    _db.SaveChanges();
                    return Ok(user);
                }
                else
                {
                    return NotFound("Registation failed!");
                }
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserLogin userLogin)
        {
            List<User> user = _db.Users.Where(x => x.Email == userLogin.Email).ToList();

            if (!VerifyPasswordHash(userLogin.Password, user[0].PasswordHash, user[0].PasswordSalt))
            {
                return BadRequest("Wrong password!");
            }

            string token = CreateToken(user[0]);
            return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Name)
            };

            string text = "DataSet-" + EncryptString(Convert.ToString(DateTime.Now), "Now") + "-" + user.Id;
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(text));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddHours(6),
                    signingCredentials: creds
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private static string EncryptString(string text, string keyString)
        {
            var key = Encoding.UTF8.GetBytes(keyString);

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        private static string DecryptString(string cipherText, string keyString)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
            var key = Encoding.UTF8.GetBytes(keyString);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
    }
}
