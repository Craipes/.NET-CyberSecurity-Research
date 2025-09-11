namespace CyberSecurity.Controllers;

public class AccountController : Controller
{
    private readonly AppDbContext context;
    private readonly CustomAuthOptions authOptions;

    public AccountController(AppDbContext context, IOptions<CustomAuthOptions> authOptions)
    {
        this.context = context;
        this.authOptions = authOptions.Value;

        if (string.IsNullOrWhiteSpace(this.authOptions.Pepper))
        {
            throw new InvalidOperationException("CustomAuthOptions.Pepper is not configured");
        }
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register([FromForm] RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var dbUser = await context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
        if (dbUser == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username");
            return View(model);
        }

        if (dbUser.IsBlocked)
        {
            ModelState.AddModelError(string.Empty, "Account is blocked. Please contact the administrator.");
            return View(model);
        }

        if (dbUser.IsPasswordInitialized)
        {
            ModelState.AddModelError(string.Empty, "Account is already initialized. Please login");
            return View(model);
        }

        // TODO: Apply password validation

        var peppered = ApplyPepper(model.Password);
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(peppered, authOptions.BCryptWorkFactor);
        dbUser.PasswordHash = passwordHash;
        dbUser.IsPasswordInitialized = true;

        context.Users.Update(dbUser);
        await context.SaveChangesAsync();

        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromForm] LoginViewModel model, string? returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var dbUser = await context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
        if (dbUser == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username");
            return View(model);
        }

        if (dbUser.IsBlocked)
        {
            ModelState.AddModelError(string.Empty, "Your account is blocked. Please contact the administrator.");
            return View(model);
        }

        if (!dbUser.IsPasswordInitialized)
        {
            ModelState.AddModelError(string.Empty, "Password is not initialized. Please register first.");
            return View(model);
        }

        var peppered = ApplyPepper(model.Password);
        if (!BCrypt.Net.BCrypt.Verify(peppered, dbUser.PasswordHash))
        {
            ModelState.AddModelError(string.Empty, "Invalid password");

            if (!dbUser.HasAdminPrivileges)
            {
                dbUser.LoginAttemptsCount++;
                if (dbUser.LoginAttemptsCount >= authOptions.MaxLoginAttempts)
                {
                    dbUser.IsBlocked = true;
                    ModelState.AddModelError(string.Empty, "Your account has been blocked due to multiple failed login attempts. Please contact the administrator.");
                }
                context.Users.Update(dbUser);
                await context.SaveChangesAsync();
            }

            return View(model);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, model.Username)
        };

        if (dbUser.HasAdminPrivileges)
        {
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
        }

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

        if (dbUser.LoginAttemptsCount > 0)
        {
            dbUser.LoginAttemptsCount = 0;
            context.Users.Update(dbUser);
            await context.SaveChangesAsync();
        }

        if (returnUrl != null && Url.IsLocalUrl(returnUrl))
        {
            return LocalRedirect(returnUrl);
        }
        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ChangePassword([FromForm] ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (User.Identity == null)
        {
            return Forbid();
        }

        var dbUser = await context.Users.FirstOrDefaultAsync(u => u.Username == User.Identity.Name);
        if (dbUser == null)
        {
            return Forbid();
        }

        var pepperedCurrent = ApplyPepper(model.CurrentPassword);
        if (!BCrypt.Net.BCrypt.Verify(pepperedCurrent, dbUser.PasswordHash))
        {
            ModelState.AddModelError(string.Empty, "Invalid current password");
            return View(model);
        }

        var pepperedNew = ApplyPepper(model.NewPassword);
        dbUser.PasswordHash = BCrypt.Net.BCrypt.HashPassword(pepperedNew, authOptions.BCryptWorkFactor);
        context.Users.Update(dbUser);
        await context.SaveChangesAsync();
        return RedirectToAction("Index", "Home");
    }

    private string ApplyPepper(string password)
    {
        // HMAC-SHA256 with server-side pepper, then Base64 to feed into BCrypt
        var key = Encoding.UTF8.GetBytes(authOptions.Pepper);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hash);
    }
}
