using System.ComponentModel.DataAnnotations;

namespace ModelLayer.DTO
{
    public class EmailDTO
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Body { get; set; }
        public string? Subject { get; set; }=string.Empty;
        public string? Token { get; set; }= string.Empty;

    }
}
