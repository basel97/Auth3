using System.ComponentModel.DataAnnotations;

namespace ModelLayer.DTO
{
    public class RegisterDTO
    {
        [Required,MaxLength(50)]
        public string FirstName { get; set; }
        [Required, MaxLength(50)]
        public string LastName { get; set; }
        [Required, MaxLength(50)]
        public string UserName { get; set; }
        [Required, MaxLength(80)]
        public string Email { get; set; }
        [Required, MaxLength(50)]
        public string Password { get; set; }
        [Required, MaxLength(50)]
        [Compare("Password",ErrorMessage ="Password Not Match")]
        public string ConfirmPassword { get; set; }

    }
}
