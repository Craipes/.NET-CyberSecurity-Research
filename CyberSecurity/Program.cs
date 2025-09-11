var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<CustomAuthOptions>(builder.Configuration.GetSection("CustomAuthOptions"));

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
    });

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var loggerFactory = services.GetRequiredService<ILoggerFactory>();
    try
    {
        AppDbContext context = services.GetRequiredService<AppDbContext>();

        if (await context.Users.FirstOrDefaultAsync(u => u.Username == "ADMIN") == null)
        {
            var adminUser = new User
            {
                Username = "ADMIN",
                HasAdminPrivileges = true,
                IsPasswordInitialized = false,
                PasswordHash = string.Empty,
                LoginAttemptsCount = 0,
                IsBlocked = false
            };
            context.Users.Add(adminUser);
            await context.SaveChangesAsync();
        }
    }
    catch (Exception ex)
    {
        var logger = loggerFactory.CreateLogger<Program>();
        logger.LogError(ex, "An error occurred seeding the DB.");
    }
}

app.Run();
