using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using WebAppIdentity;
using WebAppIdentity.Services;

var builder = WebApplication.CreateBuilder(args);

//SERVICES
#region SERVICES

builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options => {
    options.UseSqlServer(builder.Configuration.GetConnectionString("defaultConnection"));
        });

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); //necesario para generar token de recuperacion de contraseña

//configuramos la url de retorno o redirección
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = new PathString("/Accounts/Login");
    options.AccessDeniedPath = new PathString("/Accounts/BlockedAccount");
});

//configuraciones de identity
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 4;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

//autenticacion con facebook
builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = builder.Configuration["Facebook:AppId"];
    options.AppSecret = builder.Configuration["Facebook:AppSecret"];
});

//autenticacion con google
builder.Services.AddAuthentication().AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Google:ClientId"];
    options.ClientSecret = builder.Configuration["Google:ClientSecret"];
});

//email sender
builder.Services.AddTransient<IEmailSender, MailJetMailSender>();

builder.Services.AddRouting(options=>options.LowercaseUrls= true);

builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

#endregion

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

#region MIDDLEWARES

app.UseHttpsRedirection();
app.UseStaticFiles();


app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

#endregion

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
