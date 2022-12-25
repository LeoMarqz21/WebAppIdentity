using Microsoft.AspNetCore.Mvc;
using WebAppIdentity.Models.ViewModels;

namespace WebAppIdentity.Controllers
{
    public class AccountsController : Controller
    {

        public AccountsController()
        {

        }

        [HttpGet]
        public IActionResult Register()
        {
            var model = new RegisterViewModel();
            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            var model = new LoginViewModel();
            return View(model);
        }


    }
}
