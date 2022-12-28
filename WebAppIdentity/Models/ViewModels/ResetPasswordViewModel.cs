using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace WebAppIdentity.Models.ViewModels
{
    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña *")]
        public string PasswordHash { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("PasswordHash")]
        [Display(Name = "Confirmar contraseña *")]
        public string ConfirmPasswordHash { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
