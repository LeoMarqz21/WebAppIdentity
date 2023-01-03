using System.ComponentModel.DataAnnotations;

namespace WebAppIdentity.Models.ViewModels
{
    public class MultiFactorAuthenticationViewModel
    {
        //login
        [Required]
        [Display(Name = "Codigo del autenticador")]
        public string Code { get; set; }

        public string Token { get; set; }

        //QR
        public string UrlQRCode { get; set; }

    }
}
