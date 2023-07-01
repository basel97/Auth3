using System.ComponentModel.DataAnnotations;

namespace ModelLayer.DTO
{
    public class RoleSetModelDTO
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
