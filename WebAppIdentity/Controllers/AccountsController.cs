using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAppIdentity.Models;
using WebAppIdentity.Models.ViewModels;

namespace WebAppIdentity.Controllers
{
    public class AccountsController : Controller
    {
        private readonly ApplicationDbContext context;
        private readonly IMapper mapper;
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;

        public AccountsController(
            ApplicationDbContext context, IMapper mapper, 
            UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            this.context = context;
            this.mapper = mapper;
            this.userManager = userManager;
            this.signInManager = signInManager;
        } 

        [HttpGet]
        public IActionResult Register()
        {
            var model = new RegisterViewModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            //valida si no hay errores
            if(!ModelState.IsValid)
            {
                return View(model);
            }
            //mapeamos los datos de RegisterViewModel a User
            var user = mapper.Map<User>(model);
            //guardamos los registros de usuario
            var result = await userManager.CreateAsync(user, user.PasswordHash);
            //verificamos si los datos se guardaron o hubo un error
            if(result.Succeeded)
            {
                //se crea una sesión
                await signInManager.SignInAsync(user, isPersistent: false);
                //nos redirige al Home de la aplicación
                return RedirectToAction("Index", "Home");
            }
            //manejo los erores y los carga para mostrarselos al usuario
            ErrorHandler(result);
            //retornamos la vista al usuario con todos sus datos y posibles errores
            return View(model);
        }   

        [HttpGet]
        public IActionResult Login()
        {
            var model = new LoginViewModel();
            return View(model);
        }

        private void ErrorHandler(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }
    }
}
