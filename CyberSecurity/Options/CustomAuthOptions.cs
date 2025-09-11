namespace CyberSecurity.Options;

public class CustomAuthOptions
{
    public int MaxLoginAttempts { get; set; } = 3;
    public int BCryptWorkFactor { get; set; } = 13;

    // Server-side secret used to HMAC the password before BCrypt
    public string Pepper { get; set; } = string.Empty;

    public int MinPasswordLength { get; set; } = 6;
}
