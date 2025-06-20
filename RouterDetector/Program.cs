using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Models;
using RouterDetector.Services;

var builder = WebApplication.CreateBuilder(args);

// ✅ Configure EF Core with the correct connection string key from appsettings.json
builder.Services.AddDbContext<RouterDetectorContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default-Connection")));

// ✅ Register the background service for packet capture
builder.Services.AddHostedService<NetworkTrafficCaptureService>();

// ✅ Add MVC controller and view services
builder.Services.AddControllersWithViews();
builder.Services.AddSingleton<INetworkCaptureService, NetworkCaptureService>();
builder.Services.AddHostedService<NetworkTrafficCaptureService>();

// Add cookie authentication
builder.Services.AddAuthentication("Cookies")
    .AddCookie("Cookies", options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
    });

var app = builder.Build();

// ✅ Configure middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// ✅ Define default route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

app.Run();
