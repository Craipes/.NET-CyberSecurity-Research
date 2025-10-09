namespace CyberSecurity.Models;

public class LoginViewModel
{
    public required string Username { get; set; } = string.Empty;
    public required string Password { get; set; } = string.Empty;

    public string CaptchaEncryptedSeed { get; set; } = string.Empty;
    public string CaptchaResult { get; set; } = string.Empty;
}
