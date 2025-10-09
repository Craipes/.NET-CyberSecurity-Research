using Microsoft.AspNetCore.DataProtection;
using WordsCaptcha;

namespace CyberSecurity.Services;

public class WordsCaptchaService
{
    private const string ProtectorPurpose = "WordsCaptchaProtection";

    private readonly WordSearchCaptchaOptions _options;
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public WordsCaptchaService(IOptions<WordSearchCaptchaOptions> options, IDataProtectionProvider dataProtectionProvider)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _dataProtectionProvider = dataProtectionProvider ?? throw new ArgumentNullException(nameof(dataProtectionProvider));
    }

    public (char[,] grid, string encryptedSeed) GenerateCaptcha()
    {
        var captcha = new WordSearchCaptcha(_options);
        captcha.Generate();

        var protector = _dataProtectionProvider.CreateProtector(ProtectorPurpose);
        var encryptedSeed = protector.Protect(captcha.Seed.ToString());

        return (captcha.Grid, encryptedSeed);
    }

    public bool ValidateCaptcha(string encryptedSeed, IEnumerable<string> userFoundWords)
    {
        if (string.IsNullOrWhiteSpace(encryptedSeed))
        {
            throw new ArgumentNullException(nameof(encryptedSeed));
        }
        var protector = _dataProtectionProvider.CreateProtector(ProtectorPurpose);
        int seed;
        try
        {
            var decryptedSeed = protector.Unprotect(encryptedSeed);
            seed = int.Parse(decryptedSeed);
        }
        catch
        {
            return false; // Invalid encrypted seed
        }
        var captcha = new WordSearchCaptcha(_options, seed);
        captcha.Generate();
        var foundCount = userFoundWords.Intersect(captcha.HiddenWords, StringComparer.OrdinalIgnoreCase).Count();
        return foundCount >= _options.WordsRequiredToSolve;
    }
}
