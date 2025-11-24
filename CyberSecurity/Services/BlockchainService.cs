using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CyberSecurity.Services;

public class BlockchainService
{
    private readonly AppDbContext _context;
    private readonly int _difficulty;
    private static CancellationTokenSource _cancellationTokenSource = new();

    public BlockchainService(AppDbContext context, IOptions<BlockchainOptions> options)
    {
        _context = context;
        _difficulty = options.Value.Difficulty;
    }

    public async Task<List<Block>> GetChainAsync()
    {
        var chain = await _context.Blocks.OrderBy(b => b.Id).ToListAsync();
        await ValidateChainAsync(chain);
        return chain;
    }

    public async Task AddBlockAsync(string message, string username)
    {
        while (true)
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

            newBlock.MdcHash = CalculateMdcHash(newBlock);

            var miningTask = Task.Run(() => MineBlock(newBlock, _cancellationTokenSource.Token));

            try
            {
                await miningTask;

                if (miningTask.Result) // Mining was successful
                {
                    // Brief moment of concurrency risk. A lock could be used for higher-volume scenarios.
                    var currentLastBlock = await _context.Blocks.OrderByDescending(b => b.Id).FirstOrDefaultAsync();
                    if (currentLastBlock?.Hash == newBlock.PreviousHash)
                    {
                        _context.Blocks.Add(newBlock);
                        await _context.SaveChangesAsync();

                        // Signal other mining tasks to restart and create a new CTS for subsequent tasks.
                        _cancellationTokenSource.Cancel();
                        _cancellationTokenSource = new CancellationTokenSource();
                        return; // Block added, exit the loop.
                    }
                }
                // If mining was cancelled or another block was added first, the loop will restart.
            }
            catch (OperationCanceledException)
            {
                // This is expected if another block was mined. The loop will continue, restarting the process.
            }
        }
    }

    public async Task ValidateChainAsync(List<Block> chain)
    {
        var prefix = new string('0', _difficulty);
        Block? previousBlock = null;

        foreach (var block in chain)
        {
            ValidateBlock(block, previousBlock, prefix);
            previousBlock = block;
        }

        await Task.CompletedTask; // To make the method async as per its name
    }

    private static void ValidateBlock(Block block, Block? previousBlock, string prefix)
    {
        var mdcHashIsValid = CalculateMdcHash(block) == block.MdcHash;
        var hashIsValid = CalculateHash(block) == block.Hash;
        var hashMeetsDifficulty = block.Hash.StartsWith(prefix);

        bool previousHashIsValid;
        if (previousBlock != null)
        {
            previousHashIsValid = block.PreviousHash == previousBlock.Hash;
        }
        else
        {
            // For the genesis block, we can add a specific check if needed,
            // e.g., ensuring PreviousHash is "0".
            previousHashIsValid = block.PreviousHash == "0";
        }

        block.IsValid = mdcHashIsValid && hashIsValid && hashMeetsDifficulty && previousHashIsValid;
    }

    private bool MineBlock(Block block, CancellationToken token)
    {
        var prefix = new string('0', _difficulty);
        do
        {
            if (token.IsCancellationRequested)
            {
                return false; // Mining was cancelled
            }
            block.Nonce++;
            block.Hash = CalculateHash(block);
        } while (!block.Hash.StartsWith(prefix));
        return true; // Mining succeeded
    }

    private static string CalculateMdcHash(Block block)
    {
        var input = $"{block.Timestamp}-{block.PreviousHash}-{block.Message}-{block.Username}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    private static string CalculateHash(Block block)
    {
        var input = $"{block.MdcHash}-{block.Nonce}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    public async Task EnsureGenesisBlockAsync()
    {
        if (!await _context.Blocks.AnyAsync())
        {
            var genesisBlock = new Block
            {
                Timestamp = DateTime.UtcNow,
                Message = "Genesis Block",
                Username = "System",
                PreviousHash = "0",
                Nonce = 0
            };

            genesisBlock.MdcHash = CalculateMdcHash(genesisBlock);
            
            MineBlock(genesisBlock, CancellationToken.None);

            _context.Blocks.Add(genesisBlock);
            await _context.SaveChangesAsync();
        }
    }
}
