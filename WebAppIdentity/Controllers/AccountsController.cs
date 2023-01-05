using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using WebAppIdentity.Models;
using WebAppIdentity.Models.ViewModels;

namespace WebAppIdentity.Controllers
{
    [Authorize]
    public class AccountsController : Controller
    {
        private readonly ApplicationDbContext context;
        private readonly IMapper mapper;
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly ILogger<AccountsController> logger;
        private readonly IEmailSender emailSender;
        private readonly UrlEncoder urlEncoder;
        private readonly RoleManager<IdentityRole> roleManager;

        public AccountsController(
            ApplicationDbContext context, IMapper mapper, 
            UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<AccountsController> logger, IEmailSender emailSender, UrlEncoder urlEncoder, 
            RoleManager<IdentityRole> roleManager)
        {
            this.context = context;
            this.mapper = mapper;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
            this.emailSender = emailSender;
            this.urlEncoder = urlEncoder;
            this.roleManager = roleManager;
        } 

        [HttpGet]
        [AllowAnonymous]
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
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            //rol
            if(!await roleManager.RoleExistsAsync("user"))
            {
                //crear rol
                await roleManager.CreateAsync(new IdentityRole("user"));

            }

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
                //asignar role
                await userManager.AddToRoleAsync(user, "user");
                //generar token para confirmacion de registro
                var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
                //url de retorno
                var confirmEmailUrl = Url.Action("ConfirmEmail", "Accounts", new { userId = user.Id, code = token }, HttpContext.Request.Scheme);
                //mensaje de email
                var htmlMessage = $"Confirmar cuenta, Click Aqui: <a href=\"{confirmEmailUrl}\">Link</a>";
                //enviamos email de recuperacion de contraseña
                await emailSender.SendEmailAsync(model.Email, "Confirmación de cuenta - WAI", htmlMessage);
                //se crea una sesión
                await signInManager.SignInAsync(user, isPersistent: false);
                //nos redirige al Home de la aplicación
                return LocalRedirect(returnUrl);
            }
            //manejo los erores y los carga para mostrarselos al usuario
            ErrorHandler(result);
            //retornamos la vista al usuario con todos sus datos y posibles errores
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> confirmEmail(string userId = null, string code = null)
        {
            if(userId is null && code is null)
            {
                return View("Error404");
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user is null) return View("Error404");
            //confirmamos el la cuenta atraves del token recibido en mi email
            var result = await userManager.ConfirmEmailAsync(user, code);

            if(result.Succeeded)
            {
                return View("ConfirmEmail");
            }

            return View("Error404");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmEmail()
        {
            return View();  
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewData["returnUrl"] = returnUrl;
            var model = new LoginViewModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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
            //MFA
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(VerifyAuthenticationCode), new { returnUrl, model.RememberMe });
            }

            //resultado de intento de inicio de sesion
            if (result.Succeeded)
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

        [HttpGet]
        [AllowAnonymous]
        public IActionResult RecoverPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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
        [AllowAnonymous]
        public IActionResult ResetPasswordInProcess()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
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
        [AllowAnonymous]
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

        [AllowAnonymous]
        public IActionResult ConfirmResetPassword()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Error404()
        {
            return View();
        }

        //---------------------------------------------------------
        //facebook, google, twitter
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalAccess(string provider, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            //capturamos la url de retorno
            ViewData["returnUrl"] = returnUrl;
            var redirection = Url.Action("ExternalAccessCallback", "Accounts", new { ReturnUrl = returnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirection);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalAccessCallback(string returnUrl = null, string error = null)
        {
            if(error is not null)
            {
                ModelState.AddModelError(string.Empty, $"Error en acceso externo: {error}");
                return View(nameof(Login));
            }
            var info = await signInManager.GetExternalLoginInfoAsync();
            if(info is null)
            {
                return RedirectToAction(nameof(Login));
            }

            //acceder con usuario en el proveedor externo
            var result = await signInManager
                .ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            
            if(result.Succeeded)
            {   //actualizando tokens de acceso
                await signInManager.UpdateExternalAuthenticationTokensAsync(externalLogin: info);
                return LocalRedirect(returnUrl);
            }

            if(result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(VerifyAuthenticationCode), new { returnUrl = returnUrl });
            }
            else
            {
                ViewData["returnUrl"] = returnUrl;
                ViewData["providerName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ConfirmExternalAccess", new ConfirmExternalAccessViewModel { Email = email, Name = name});
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmExternalAccess(ConfirmExternalAccessViewModel model, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if(!ModelState.IsValid)
            {
                return View(model);
            }
            //obtener la informacion del usuario del proveedor externo
            var info = await signInManager.GetExternalLoginInfoAsync();
            if(info is null)
            {
                return View(model);
            }

            var user = new User { UserName = model.UserName, Name = model.Name, Email = model.Email };
            var result = await userManager.CreateAsync(user);

            if(result.Succeeded)
            {
                result = await userManager.AddLoginAsync(user, info);
                if(result.Succeeded)
                {
                    await signInManager.SignInAsync(user, isPersistent: false);
                    await signInManager.UpdateExternalAuthenticationTokensAsync(info);
                    return LocalRedirect(returnUrl);
                }

            }
            ErrorHandler(result);

            return View(model);
        }


        //MFA = Multi-Factor Authentication
        //-----------------------------------------------------------------

        [HttpGet]
        public async Task<IActionResult> EnableMFA()
        {
            //QR
            string authUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&digits=6";

            var user = await userManager.GetUserAsync(User);
            await userManager.ResetAuthenticatorKeyAsync(user);
            var token = await userManager.GetAuthenticatorKeyAsync(user);

            //habilitar codigo QR
            string authUrl = string.Format(authUrlFormat, urlEncoder.Encode("WAI"), urlEncoder.Encode(user.Email), token);

            var mfa = new MultiFactorAuthenticationViewModel { Token = token, UrlQRCode = authUrl };
            return View(mfa);
        }

        [HttpGet]
        public async Task<IActionResult> DisableMFA()
        {
            var user = await userManager.GetUserAsync(User);
            await userManager.ResetAuthenticatorKeyAsync(user);
            await userManager.SetTwoFactorEnabledAsync(user, enabled: false);
            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
        public async Task<IActionResult> EnableMFA(MultiFactorAuthenticationViewModel model)
        {
            if(!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await userManager.GetUserAsync(User);
            var succeded = await userManager
                .VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if(succeded)
            {
                await userManager.SetTwoFactorEnabledAsync(user, true);
                return RedirectToAction(nameof(ConfirmEnableMFA));
            }
            ModelState.AddModelError("verificacion", "Su verificacion de dos factores fallo o no fue aceptada");
            return View(model);
        }

        [HttpGet]
        public IActionResult ConfirmEnableMFA()
        {
            //TODO
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticationCode(bool remenberData, string returnUrl = null)
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user is null)
                return View(nameof(Error404));
            ViewData["returnUrl"] = returnUrl ?? Url.Content("~/");
            var model = new VerifyAuthenticationCodeViewModel { RememberData = remenberData, ReturnUrl = returnUrl };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticationCode(VerifyAuthenticationCodeViewModel model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if(!ModelState.IsValid)
                return View(model);

            var result = await signInManager
                .TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberData, rememberClient: true);

            if(result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }
            if(result.IsLockedOut)
            {
                return View(nameof(Locked));
            }
            ModelState.AddModelError(string.Empty, "Su intento de autenticacion no ha sido validado");
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Locked()
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
