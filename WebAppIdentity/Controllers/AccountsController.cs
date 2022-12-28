using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
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
        private readonly IEmailSender emailSender;

        public AccountsController(
            ApplicationDbContext context, IMapper mapper, 
            UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<AccountsController> logger, IEmailSender emailSender)
        {
            this.context = context;
            this.mapper = mapper;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
            this.emailSender = emailSender;
        } 

        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            //si returnUrl es null, este se llenara con la direccion a pagina raiz
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["returnUrl"] = returnUrl;
            var model = new RegisterViewModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["returnUrl"] = returnUrl;
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
                return LocalRedirect(returnUrl);
            }
            logger.LogInformation("hubo un error en el guardado de datos del metodo de registro");
            //manejo los erores y los carga para mostrarselos al usuario
            ErrorHandler(result);
            //retornamos la vista al usuario con todos sus datos y posibles errores
            return View(model);
        }   

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["returnUrl"] = returnUrl;
            var model = new LoginViewModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            //capturamos la url de retorno
            ViewData["returnUrl"] = returnUrl;
            //verificamos si existen errores
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            //ingresamos datos de inicio de sesion
            var result = await signInManager
                .PasswordSignInAsync(model.UserName, model.PasswordHash, isPersistent: model.RememberMe, lockoutOnFailure: true);
            //verificamos si no se ha bloqueado esta cuenta
            if(result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Espere un minuto y luego intente iniciar sesion");
                return View(model);
            }
            //resultado de intento de inicio de sesion
            if(result.Succeeded)
            {
                //todo va bien
                //return RedirectToAction("Index", "Home");
                return LocalRedirect(returnUrl);
            }else
            {
                //hubo errores y estos se retornara junto a la vista nuevamente
                ModelState.AddModelError(string.Empty, "Access denied!");
            }
            logger.LogInformation("hubo un error en el metodo de inicio de sesion");
            //retornamos la vista
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            //metodo de cierre de sesion
            await signInManager.SignOutAsync();
            return RedirectToAction("Login", "Accounts");
        }

        public IActionResult RecoverPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RecoverPassword(RecoverPasswordViewModel model)
        {
            //validamos que no haya errores
            if(!ModelState.IsValid)
            {
                return View(model);
            }
            //buscamos usuario con el email proporcionado
            var user = await userManager.FindByEmailAsync(model.Email);
            
            if (user == null)
            {
                //mensaje de error en caso de que no exista un usuario con dicho email
                ModelState.AddModelError(string.Empty, "No existe registro con este email");
                return View(model);
            }
            //token que validara la recuperacion de la contraseña
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            //url para recuperar contraseña
            var returnUrl = Url.Action("ResetPassword", "Accounts", new { userId = user.Id, code = token }, HttpContext.Request.Scheme);
            //mensaje de email
            var htmlMessage = $"Recuperar contraseña, Click Aqui: <a href=\"{returnUrl}\">Link</a>";
            //enviamos email de recuperacion de contraseña
            await emailSender.SendEmailAsync(model.Email, "Recuperar contraseña - WAI", htmlMessage);
            //redirigimos a una vista de confirmacion de envio de email para recuperacion de contraseña
            return RedirectToAction("ResetPasswordInProcess", "Accounts");
        }

        [HttpGet]
        public IActionResult ResetPasswordInProcess()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            if(code is null)
            {
                return View("ErrorResetPassword");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (model is null)
            {
                return View("ErrorResetPassword");
            }
            //verificamos que exista el usuario con el email enviado
            var user = await userManager.FindByEmailAsync(model.Email);

            if(user is null)
            {
                return View("ErrorResetPassword");
            }
            //cambiamos la contraseña, validando el codigo o token antes obtenido
            var result = await userManager.ResetPasswordAsync(user, model.Code, model.PasswordHash);

            if (result.Succeeded)
            {
                return RedirectToAction("ConfirmResetPassword");
            }

            ErrorHandler(result);
            return View(model);
        }

        public IActionResult ConfirmResetPassword()
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
