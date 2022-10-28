using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models
{
    public class User
    {
        [Key]
        [DisplayName("Id")]
        public int Id { get; set; } = 0;
        [Required]
        [DisplayName("Name")]
        public string Name { get; set; } = string.Empty;
        [Required]
        [DisplayName("Email")]
        public string Email { get; set; } = string.Empty;
        [Required]
        [DisplayName("PasswordHash")]
        public byte[] PasswordHash { get; set; }
        [Required]
        [DisplayName("PasswordSalt")]
        public byte[] PasswordSalt { get; set; } 
    }

    public struct UserLogin {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public struct UserRegister
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
