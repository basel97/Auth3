using System.ComponentModel.DataAnnotations;

namespace ModelLayer.DTO
{
    public class ResetPasswordModelDTO
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Required,Compare("Password")]
        public string ConfirmPassword { get; set; }
        [Required]
        public string Token { get; set; }

    }
}
