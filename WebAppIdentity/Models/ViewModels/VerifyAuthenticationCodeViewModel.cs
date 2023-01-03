using System.ComponentModel.DataAnnotations;

namespace WebAppIdentity.Models.ViewModels
{
    public class VerifyAuthenticationCodeViewModel
    {
        [Required]
        [Display(Name = "Codigo autenticador")]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [Display(Name = "Recordar Datos")]
        public bool RememberData { get; set; }
    }
}
