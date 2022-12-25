using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebAppIdentity;

var builder = WebApplication.CreateBuilder(args);

//SERVICES
#region SERVICES

builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options => {
    options.UseSqlServer(builder.Configuration.GetConnectionString("defaultConnection"));
        });

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

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
