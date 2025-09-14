namespace CyberSecurity;

public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        var loggerFactory = services.GetRequiredService<ILoggerFactory>();
        try
        {
            UsersService usersService = services.GetRequiredService<UsersService>();

            if (await usersService.GetByUsernameAsync("ADMIN") == null)
            {
                var adminUser = new User
                {
                    Username = "ADMIN",
                    HasAdminPrivileges = true,
                };
                await usersService.AddUserAndSaveAsync(adminUser);
            }
        }
        catch (Exception ex)
        {
            var logger = loggerFactory.CreateLogger<Program>();
            logger.LogError(ex, "An error occurred seeding the DB.");
        }
    }
}
