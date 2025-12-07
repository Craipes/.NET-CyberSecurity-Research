namespace CyberSecurity.Controllers;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly UsersService usersService;
    private readonly ILogger<AdminController> logger;

    public AdminController(UsersService usersService, ILogger<AdminController> logger)
    {
        this.usersService = usersService;
        this.logger = logger;
    }

    public async Task<IActionResult> Users()
    {
        var users = await usersService.GetAllAsync();
        return View(users);
    }

    [HttpGet]
    public IActionResult AddUser()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> AddUser([FromForm] AddUserViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (model.Username != null && model.Username.Any(char.IsWhiteSpace))
        {
            ModelState.AddModelError(string.Empty, "Username must not contain white space characters");
            logger.ZLogTrace($"Admin tried to add a user with whitespace in the username");
            return View(model);
        }

        if (string.IsNullOrWhiteSpace(model.Username) || model.Username.Length < 3 || model.Username.Length > 24)
        {
            ModelState.AddModelError(string.Empty, "Username must be 3-24 characters long");
            logger.ZLogTrace($"Admin tried to add a user with an invalid username length");
            return View(model);
        }

        var dbUser = await usersService.GetByUsernameAsync(model.Username);
        if (dbUser != null)
        {
            ModelState.AddModelError(string.Empty, "Username is already taken");
            logger.ZLogTrace($"Admin tried to add a user with an already taken username");
            return View(model);
        }

        var newUser = new User
        {
            Username = model.Username
        };

        await usersService.AddUserAndSaveAsync(newUser);
        logger.ZLogInformation($"Admin added a new user: {newUser.Id}");
        return RedirectToAction("Users");
    }

    [HttpPost]
    public async Task<IActionResult> BlockUser([FromForm] string? username)
    {
        return await ToggleUserBlock(username, true);
    }

    [HttpPost]
    public async Task<IActionResult> UnblockUser([FromForm] string? username)
    {
        return await ToggleUserBlock(username, false);
    }

    private async Task<IActionResult> ToggleUserBlock(string? username, bool block)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            logger.ZLogTrace($"Admin tried to block/unblock a user without providing a username");
            return BadRequest("Username is required");
        }

        var dbUser = await usersService.GetByUsernameAsync(username);
        if (dbUser == null)
        {
            logger.ZLogTrace($"Admin tried to block/unblock a non-existing user: {username}");
            return NotFound("User not found");
        }
        if (dbUser.Username == User.Identity?.Name)
        {
            logger.ZLogTrace($"Admin tried to block/unblock their own account");
            return BadRequest("You cannot block/unblock your own account");
        }
        if (dbUser.HasAdminPrivileges)
        {
            logger.ZLogTrace($"Admin tried to block/unblock another admin account: {dbUser.Id}");
            return BadRequest("You cannot block/unblock an admin account");
        }

        dbUser.IsBlocked = block;
        await usersService.UpdateUserAndSaveAsync(dbUser);
        logger.ZLogInformation($"Admin {(block ? "blocked" : "unblocked")} user: {dbUser.Id}");
        return RedirectToAction("Users");
    }

    [HttpPost]
    public async Task<IActionResult> EnablePasswordRestrictions([FromForm] string? username)
    {
        return await ToggleUserPasswordRestrictions(username, true);
    }

    [HttpPost]
    public async Task<IActionResult> DisablePasswordRestrictions([FromForm] string? username)
    {
        return await ToggleUserPasswordRestrictions(username, false);
    }

    private async Task<IActionResult> ToggleUserPasswordRestrictions(string? username, bool enable)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            logger.ZLogTrace($"Admin tried to enable/disable password restrictions without providing a username");
            return BadRequest("Username is required");
        }
        var dbUser = await usersService.GetByUsernameAsync(username);
        if (dbUser == null)
        {
            logger.ZLogTrace($"Admin tried to enable/disable password restrictions for a non-existing user: {username}");
            return NotFound("User not found");
        }

        dbUser.PasswordRestrictionsEnabled = enable;
        await usersService.UpdateUserAndSaveAsync(dbUser);
        logger.ZLogInformation($"Admin {(enable ? "enabled" : "disabled")} password restrictions for user: {dbUser.Id}");
        return RedirectToAction("Users");
    }

    [HttpPost]
    public async Task<IActionResult> GrantFullAccess([FromForm] string? username)
    {
        return await ToggleFullAccess(username, true);
    }

    [HttpPost]
    public async Task<IActionResult> RevokeFullAccess([FromForm] string? username)
    {
        return await ToggleFullAccess(username, false);
    }

    private async Task<IActionResult> ToggleFullAccess(string? username, bool grant)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            logger.ZLogTrace($"Admin tried to grant/revoke full access without providing a username");
            return BadRequest("Username is required");
        }
        var dbUser = await usersService.GetByUsernameAsync(username);
        if (dbUser == null)
        {
            logger.ZLogTrace($"Admin tried to grant/revoke full access for a non-existing user: {username}");
            return NotFound("User not found");
        }

        dbUser.HasFullAccess = grant;
        await usersService.UpdateUserAndSaveAsync(dbUser);
        logger.ZLogInformation($"Admin {(grant ? "granted" : "revoked")} full access for user: {dbUser.Id}");
        return RedirectToAction("Users");
    }
}
