namespace CyberSecurity.Models
{
    public class RsaViewModel
    {
        public string? PublicKey { get; set; }
        public string? OriginalText { get; set; }
        public string? EncryptedText { get; set; }
        public string? EncryptedTextToDecrypt { get; set; }
        public string? DecryptedText { get; set; }
    }
}
