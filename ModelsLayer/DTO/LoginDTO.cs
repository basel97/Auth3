using System.ComponentModel.DataAnnotations;

namespace ModelLayer.DTO
{
    public class LoginDTO
    {
        [Required, MaxLength(80)]
        public string Email { get; set; }
        [Required, MaxLength(50)]
        public string Password { get; set; }
    }
}
