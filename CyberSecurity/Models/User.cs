namespace CyberSecurity.Models;

public class User
{
    [Key] [MinLength(4)] public required string Username { get; set; }
    public bool HasAdminPrivileges { get; set; }
    public string PasswordHash { get; set; } = "";
    public bool IsPasswordInitialized { get; set; }
    public int LoginAttemptsCount { get; set; }
    public bool IsBlocked { get; set; }
}
