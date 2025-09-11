namespace CyberSecurity.Models;

public class User
{
    [Key] [MinLength(4)] public required string Username { get; set; }
    public required bool HasAdminPrivileges { get; set; }
    public required string PasswordHash { get; set; }
    public required bool IsPasswordInitialized { get; set; }
    public required int LoginAttemptsCount { get; set; }
    public required bool IsBlocked { get; set; }
}
