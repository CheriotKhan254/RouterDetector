using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using RouterDetector.Data;
using RouterDetector.Services;

var builder = WebApplication.CreateBuilder(args);

// ✅ Configure EF Core with the correct connection string key from appsettings.json
builder.Services.AddDbContext<RouterDetectorContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default-Connection")));

// ✅ Register the background service for packet capture
builder.Services.AddHostedService<NetworkTrafficCaptureService>();

// ✅ Add MVC controller and view services
builder.Services.AddControllersWithViews();

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

app.UseAuthorization();

// ✅ Define default route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
