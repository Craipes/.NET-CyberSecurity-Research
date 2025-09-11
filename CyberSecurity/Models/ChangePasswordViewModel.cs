namespace CyberSecurity.Models;

public class ChangePasswordViewModel
{
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    [Compare(nameof(NewPassword))] public string ConfirmNewPassword { get; set; } = string.Empty;
}
