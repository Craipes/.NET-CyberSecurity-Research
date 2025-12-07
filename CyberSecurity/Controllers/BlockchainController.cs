namespace CyberSecurity.Controllers;

[Authorize]
public class BlockchainController : Controller
{
    private readonly BlockchainService _blockchainService;

    public BlockchainController(BlockchainService blockchainService)
    {
        _blockchainService = blockchainService;
    }

    public async Task<IActionResult> Index()
    {
        var chain = await _blockchainService.GetChainAsync();
        var model = new BlockchainViewModel
        {
            Chain = chain
        };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddBlock([Bind(Prefix = "AddBlock")] AddBlockViewModel model)
    {
        if (!User.IsInRole("FullAccess"))
        {
            TempData["ErrorMessage"] = "You do not have permission to add new transactions. Please contact the administrator to get full access.";
            return RedirectToAction("Index");
        }

        if (ModelState.IsValid && model != null)
        {
            var username = User.Identity?.Name ?? "anonymous";
            await _blockchainService.AddBlockAsync(model.NewMessage, username);
        }

        return RedirectToAction("Index");
    }
}
