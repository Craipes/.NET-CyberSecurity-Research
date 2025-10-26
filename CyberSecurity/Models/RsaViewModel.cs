namespace CyberSecurity.Models
{
    public class RsaViewModel
    {
        public string? PublicKey { get; set; }
        public string? OriginalText { get; set; }
        public string? EncryptedText { get; set; }
        public string? EncryptedTextToDecrypt { get; set; }
        public string? DecryptedText { get; set; }

        // For MD5 Hashing
        public string? TextToHash { get; set; }
        public string? HashedText { get; set; }

        // For Digital Signature
        public string? TextToSign { get; set; }
        public string? DigitalSignature { get; set; }
        public string? TextToVerify { get; set; }
        public string? SignatureToVerify { get; set; }
        public string? VerificationResult { get; set; }
    }
}
