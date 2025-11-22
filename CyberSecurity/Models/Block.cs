namespace CyberSecurity.Models;

public class Block
{
    [Key]
    public int Id { get; set; }

    [Required]
    public DateTime Timestamp { get; set; }

    [Required]
    public string Message { get; set; } = string.Empty;

    [Required]
    public string Username { get; set; } = string.Empty;

    public long Nonce { get; set; }

    [Required]
    public string Hash { get; set; } = string.Empty;

    [Required]
    public string MdcHash { get; set; } = string.Empty;

    [Required]
    public string PreviousHash { get; set; } = string.Empty;
}
