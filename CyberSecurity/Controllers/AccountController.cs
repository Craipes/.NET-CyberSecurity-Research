using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Text.RegularExpressions;

namespace CyberSecurity.Controllers;

public class AccountController : Controller
{
    private readonly UsersService usersService;
    private readonly CustomAuthOptions authOptions;
    private readonly ILogger<AccountController> logger;

    public AccountController(UsersService usersService, IOptions<CustomAuthOptions> authOptions, ILogger<AccountController> logger)
    {
        this.usersService = usersService;
        this.logger = logger;
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

        var dbUser = await usersService.GetByUsernameAsync(model.Username);
        if (dbUser == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username");
            logger.ZLogInformation($"User tried to register with an invalid username: {model.Username}");
            return View(model);
        }

        if (dbUser.IsBlocked)
        {
            ModelState.AddModelError(string.Empty, "Account is blocked. Please contact the administrator.");
            logger.ZLogInformation($"Blocked user has tried to register: {dbUser.Id}");
            return View(model);
        }

        if (dbUser.IsPasswordInitialized)
        {
            ModelState.AddModelError(string.Empty, "Account is already initialized. Please login");
            logger.ZLogInformation($"User has tried to register an already initialized account: {dbUser.Id}");
            return View(model);
        }

        model.Password = model.Password.Trim();
        if (!ValidatePassword(dbUser, model.Password, ModelState))
        {
            logger.ZLogInformation($"User has tried to register with an invalid password: {dbUser.Id}");
            return View(model);
        }

        var peppered = ApplyPepper(model.Password);
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(peppered, authOptions.BCryptWorkFactor);
        dbUser.PasswordHash = passwordHash;
        dbUser.IsPasswordInitialized = true;

        logger.ZLogInformation($"User registered: {dbUser.Id}");

        await usersService.UpdateUserAndSaveAsync(dbUser);

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

        var dbUser = await usersService.GetByUsernameAsync(model.Username);
        if (dbUser == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            logger.ZLogInformation($"User tried to login with an invalid username: {model.Username}");
            return View(model);
        }

        if (dbUser.IsBlocked)
        {
            ModelState.AddModelError(string.Empty, "Your account is blocked. Please contact the administrator.");
            logger.ZLogInformation($"Blocked user tried to login: {dbUser.Id}");
            return View(model);
        }

        if (!dbUser.IsPasswordInitialized)
        {
            ModelState.AddModelError(string.Empty, "Password is not initialized. Please register first.");
            logger.ZLogInformation($"User with uninitialized password tried to login: {dbUser.Id}");
            return View(model);
        }

        model.Password = model.Password.Trim();
        var peppered = ApplyPepper(model.Password);
        if (!BCrypt.Net.BCrypt.Verify(peppered, dbUser.PasswordHash))
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            logger.ZLogInformation($"User tried to login with an invalid password: {dbUser.Id}");

            if (!dbUser.HasAdminPrivileges)
            {
                dbUser.LoginAttemptsCount++;
                if (dbUser.LoginAttemptsCount >= authOptions.MaxLoginAttempts)
                {
                    dbUser.IsBlocked = true;
                    ModelState.AddModelError(string.Empty, "Your account has been blocked due to multiple failed login attempts. Please contact the administrator.");
                    logger.ZLogInformation($"User account has been blocked due to multiple failed login attempts: {dbUser.Id}");
                }
                await usersService.UpdateUserAndSaveAsync(dbUser);
            }

            return View(model);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, dbUser.Id.ToString()),
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
            await usersService.UpdateUserAndSaveAsync(dbUser);
        }

        logger.ZLogInformation($"User logged in: {dbUser.Id}");

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
        logger.ZLogInformation($"User logged out: {User.FindFirstValue(ClaimTypes.NameIdentifier)}");
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

        var dbUser = await usersService.GetByUsernameAsync(User.Identity.Name);
        if (dbUser == null)
        {
            return Forbid();
        }

        model.CurrentPassword = model.CurrentPassword.Trim();
        var pepperedCurrent = ApplyPepper(model.CurrentPassword);
        if (!BCrypt.Net.BCrypt.Verify(pepperedCurrent, dbUser.PasswordHash))
        {
            ModelState.AddModelError(string.Empty, "Invalid current password");
            logger.ZLogInformation($"User tried to change password with an invalid current password: {dbUser.Id}");
            return View(model);
        }

        model.NewPassword = model.NewPassword.Trim();
        if (!ValidatePassword(dbUser, model.NewPassword, ModelState))
        {
            logger.ZLogInformation($"User tried to change password with an invalid new password: {dbUser.Id}");
            return View(model);
        }

        var pepperedNew = ApplyPepper(model.NewPassword);
        dbUser.PasswordHash = BCrypt.Net.BCrypt.HashPassword(pepperedNew, authOptions.BCryptWorkFactor);
        await usersService.UpdateUserAndSaveAsync(dbUser);

        logger.ZLogInformation($"User changed password: {dbUser.Id}");

        return RedirectToAction("Index", "Home");
    }

    private bool ValidatePassword(User user, string password, ModelStateDictionary? modelState)
    {
        if (password.Length < authOptions.MinPasswordLength)
        {
            modelState?.AddModelError(string.Empty, $"Password must be at least {authOptions.MinPasswordLength} characters long");
            return false;
        }

        // Custom password restrictions could be applied here
        if (user.PasswordRestrictionsEnabled)
        {
            if (!Regex.IsMatch(password, "[0-9]+[.,;:-]+[0-9]+"))
            {
                modelState?.AddModelError(string.Empty, "Your password has a restriction to be a sequence of digits, separators and digits again");
                return false;
            }
        }

        return true;
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
