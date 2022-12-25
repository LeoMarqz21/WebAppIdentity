using System.ComponentModel.DataAnnotations;

namespace WebAppIdentity.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required]
        [StringLength(maximumLength:120, MinimumLength = 5)]
        [Display(Name = "Nombre Completo *")]
        public string Name { get; set; }

        [StringLength(maximumLength:50, MinimumLength = 3)]
        [Required]
        [Display(Name = "Nombre Usuario *")]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Correo Electronico *")]
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

        [Display(Name = "Telefono")]
        public string PhoneNumber { get; set; }

        [Display(Name = "Url web")]
        public string Url { get; set; }

        [Required]
        [Display(Name = "Pais *")]
        public string Country { get; set; }

        [Display(Name = "Codigo Pais")]
        public int CountryCode { get; set; }

        [Display(Name = "Ciudad")]
        public string City { get; set; }

        [Display(Name = "Dirección")]
        public string Address { get; set; }

        [Required]
        [Display(Name = "Fecha Nacimiento *")]
        public DateTime DateOfBirth { get; set; } = DateTime.Now;

        [Required]
        [Display(Name = "Activo *")]
        public bool Active { get; set; } = true;
    }
}
