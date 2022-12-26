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
        private readonly ILogger<AccountsController> logger;

        public AccountsController(
            ApplicationDbContext context, IMapper mapper, 
            UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<AccountsController> logger)
        {
            this.context = context;
            this.mapper = mapper;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
        } 

        [HttpGet]
        public IActionResult Register()
        {
            var model = new RegisterViewModel();
            logger.LogInformation("Mostrando vista de registro");
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            logger.LogInformation("proceso de guardado de datos");
            //valida si no hay errores
            if (!ModelState.IsValid)
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
            logger.LogInformation("hubo un error en el guardado de datos del metodo de registro");
            //manejo los erores y los carga para mostrarselos al usuario
            ErrorHandler(result);
            //retornamos la vista al usuario con todos sus datos y posibles errores
            return View(model);
        }   

        [HttpGet]
        public IActionResult Login()
        {
            var model = new LoginViewModel();
            logger.LogInformation("Mostrando vista de inicio de sesion");
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            logger.LogInformation("proceso de inicio de sesion");
            //verificamos si existen errores
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            //ingresamos datos de inicio de sesion
            var result = await signInManager
                .PasswordSignInAsync(model.UserName, model.PasswordHash, isPersistent: model.RememberMe, lockoutOnFailure: false);
            //resultado de intento de inicio de sesion
            if(result.Succeeded)
            {
                //todo va bien
                return RedirectToAction("Index", "Home");
            }else
            {
                //hubo errores y estos se retornara junto a la vista nuevamente
                ModelState.AddModelError(string.Empty, "Access denied!");
            }
            logger.LogInformation("hubo un error en el metodo de inicio de sesion");
            //retornamos la vista
            return View(model);
        }

        public IActionResult RecoverPassword()
        {
            return View();
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
