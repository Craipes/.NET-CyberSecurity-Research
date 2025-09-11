namespace CyberSecurity.Controllers;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly UsersService usersService;

    public AdminController(UsersService usersService)
    {
        this.usersService = usersService;
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
            return View(model);
        }

        if (string.IsNullOrWhiteSpace(model.Username) || model.Username.Length < 3 || model.Username.Length > 24)
        {
            ModelState.AddModelError(string.Empty, "Username must be 3-24 characters long");
            return View(model);
        }

        var dbUser = await usersService.GetByUsernameAsync(model.Username);
        if (dbUser != null)
        {
            ModelState.AddModelError(string.Empty, "Username is already taken");
            return View(model);
        }

        var newUser = new User
        {
            Username = model.Username
        };

        await usersService.AddUserAndSaveAsync(newUser);
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
            return BadRequest("Username is required");
        }

        var dbUser = await usersService.GetByUsernameAsync(username);
        if (dbUser == null)
        {
            return NotFound("User not found");
        }
        if (dbUser.Username == User.Identity?.Name)
        {
            return BadRequest("You cannot block/unblock your own account");
        }
        if (dbUser.HasAdminPrivileges)
        {
            return BadRequest("You cannot block/unblock an admin account");
        }

        dbUser.IsBlocked = block;
        await usersService.UpdateUserAndSaveAsync(dbUser);
        return RedirectToAction("Users");
    }
}
