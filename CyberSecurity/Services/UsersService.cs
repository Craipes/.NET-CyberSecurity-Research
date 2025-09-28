namespace CyberSecurity.Services;

public class UsersService
{
    private readonly AppDbContext context;

    public UsersService(AppDbContext context)
    {
        this.context = context;
    }

    public async Task<List<User>> GetAllAsync()
    {
        return await context.Users.OrderBy(u => u.Username).ToListAsync();
    }

    public async Task<User?> GetByIdAsync(Guid id)
    {
        return await context.Users.FindAsync(id);
    }

    public async Task<User?> GetByUsernameAsync(string? username)
    {
        if (username == null) return null;
        return await context.Users.FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task UpdateUserAndSaveAsync(User user)
    {
        context.Users.Update(user);
        await context.SaveChangesAsync();
    }

    public async Task AddUserAndSaveAsync(User user)
    {
        context.Users.Add(user);
        await context.SaveChangesAsync();
    }
}
