using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebAppIdentity.Models
{
    public class User : IdentityUser
    {
        public string Name { get; set; }
        public string Url { get; set; }
        public string Country { get; set; }
        public int CountryCode { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public DateTime DateOfBirth { get; set; }
        public bool Active { get; set; } = true;
    }
}
