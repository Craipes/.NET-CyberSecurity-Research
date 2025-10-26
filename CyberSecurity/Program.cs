using WordsCaptcha;

var builder = WebApplication.CreateBuilder(args);

builder.Logging
    .ClearProviders()
    .AddZLoggerConsole(options =>
    {
        options.UsePlainTextFormatter(formatter =>
        {
            formatter.SetPrefixFormatter($"[{0}|{1}|{2}] ", (in MessageTemplate template, in LogInfo info) => template.Format(info.Timestamp, info.Category, info.LogLevel));
            formatter.SetExceptionFormatter((writer, ex) => Utf8StringInterpolation.Utf8String.Format(writer, $"{ex.Message}"));
        });
    })
    .AddZLoggerRollingFile(options =>
    {
        options.FilePathSelector = (dt, index) => $"Logs/{dt:yyyy-MM-dd}_{index}.log";
        options.RollingSizeKB = 1024 * 5;
        options.UsePlainTextFormatter(formatter =>
        {
            formatter.SetPrefixFormatter($"[{0}|{1}|{2}] ", (in MessageTemplate template, in LogInfo info) => template.Format(info.Timestamp, info.Category, info.LogLevel));
            formatter.SetExceptionFormatter((writer, ex) => Utf8StringInterpolation.Utf8String.Format(writer, $"{ex.Message}"));
        });
    });

builder.Services.Configure<CustomAuthOptions>(builder.Configuration.GetSection("CustomAuthOptions"));
builder.Services.Configure<WordSearchCaptchaOptions>(builder.Configuration.GetSection("WordSearchCaptchaOptions"));

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

builder.Services.AddDataProtection();
builder.Services.AddScoped<UsersService>();
builder.Services.AddScoped<WordsCaptchaService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
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

app.UseSession();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DbSeeder.SeedAsync(services);
}

app.Run();