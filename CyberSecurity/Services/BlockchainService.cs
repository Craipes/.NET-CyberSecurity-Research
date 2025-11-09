namespace CyberSecurity.Services;

public class BlockchainService
{
    private readonly AppDbContext _context;
    private readonly int _difficulty;

    public BlockchainService(AppDbContext context, IOptions<BlockchainOptions> options)
    {
        _context = context;
        _difficulty = options.Value.Difficulty;
    }

    public async Task<List<Block>> GetChainAsync()
    {
        return await _context.Blocks.OrderBy(b => b.Id).ToListAsync();
    }

    public async Task AddBlockAsync(string message, string username)
    {
        var lastBlock = await _context.Blocks.OrderByDescending(b => b.Id).FirstOrDefaultAsync();
        var previousHash = lastBlock?.Hash ?? "0";

        var newBlock = new Block
        {
            Timestamp = DateTime.UtcNow,
            Message = message,
            Username = username,
            PreviousHash = previousHash
        };

        await Task.Run(() => MineBlock(newBlock));

        _context.Blocks.Add(newBlock);
        await _context.SaveChangesAsync();
    }

    private void MineBlock(Block block)
    {
        var prefix = new string('0', _difficulty);
        do
        {
            block.Nonce++;
            block.Hash = CalculateHash(block);
        } while (!block.Hash.StartsWith(prefix));
    }

    private static string CalculateHash(Block block)
    {
        var input = $"{block.Timestamp}-{block.PreviousHash}-{block.Message}-{block.Username}-{block.Nonce}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    public async Task EnsureGenesisBlockAsync()
    {
        if (!_context.Blocks.Any())
        {
            var genesisBlock = new Block
            {
                Timestamp = DateTime.UtcNow,
                Message = "Genesis Block",
                Username = "System",
                PreviousHash = "0",
                Nonce = 0
            };
            genesisBlock.Hash = CalculateHash(genesisBlock);
            
            MineBlock(genesisBlock);

            _context.Blocks.Add(genesisBlock);
            await _context.SaveChangesAsync();
        }
    }
}
