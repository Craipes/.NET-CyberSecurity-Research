namespace WordsCaptcha;

/// <summary>
/// Generates a word search captcha based on provided options.
/// </summary>
public class WordSearchCaptcha
{
    private readonly (int dX, int dY)[] _directions;

    private static readonly (int dX, int dY)[] straightDirections =
        [
            (1, 0), (0, 1)
        ];

    private static readonly (int dX, int dY)[] straightReverseDirections =
        [
            (1, 0), (-1, 0), (0, 1), (0, -1)
        ];

    private static readonly (int dX, int dY)[] withDiagonalDirections =
        [
            (1, 0), (0, 1), // Horizontal and Vertical
            (1, 1), (1, -1) // Diagonals
        ];

    private static readonly (int dX, int dY)[] withDiagonalReverseDirections =
        [
            (1, 0), (-1, 0), (0, 1), (0, -1), // Horizontal and Vertical
            (1, 1), (-1, -1), (1, -1), (-1, 1) // Diagonals
        ];

    private readonly WordSearchCaptchaOptions _options;
    private readonly char[,] _grid;
    private Random _random;

    /// <summary>
    /// The generated word search grid.
    /// </summary>
    public char[,] Grid => _grid;

    /// <summary>
    /// The seed used by the random number generator.
    /// </summary>
    public int Seed { get; private set; }

    /// <summary>
    /// The list of words that were successfully hidden in the grid.
    /// </summary>
    public List<string> HiddenWords { get; private set; } = [];

    /// <summary>
    /// Initializes a new instance of the WordSearchCaptcha class.
    /// </summary>
    /// <param name="options">The configuration for the captcha.</param>
    public WordSearchCaptcha(WordSearchCaptchaOptions options) : this(options, Random.Shared.Next())
    {
    }

    /// <summary>
    /// Initializes a new instance of the WordSearchCaptcha class with specified seed.
    /// </summary>
    /// <param name="options">The configuration for the captcha.</param>
    /// <param name="seed">The seed for the random number generator.</param>
    public WordSearchCaptcha(WordSearchCaptchaOptions options, int seed)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (_options.TotalWordsToHide < _options.WordsRequiredToSolve)
        {
            throw new ArgumentException("Total words to hide (N) must be greater than or equal to words required to solve (M).");
        }
        _grid = new char[_options.GridHeight, _options.GridWidth];

        Seed = seed;
        _random = new Random(Seed);

        if (_options.IncludeDiagonal)
        {
            if (_options.IncludeReverse)
            {
                _directions = withDiagonalReverseDirections;
            }
            else
            {
                _directions = withDiagonalDirections;
            }
        }
        else
        {
            if (_options.IncludeReverse)
            {
                _directions = straightReverseDirections;
            }
            else
            {
                _directions = straightDirections;
            }
        }
    }

    /// <summary>
    /// Generates the word search grid.
    /// </summary>
    public void Generate()
    {
        var wordsPool = _options.WordsPoolFilePath != null
            ? File.ReadAllLines(_options.WordsPoolFilePath).Where(line => !string.IsNullOrWhiteSpace(line)).Select(line => line.Trim())
            : _options.WordPool;

        // Filter out words that are too long to fit in the grid in any direction
        var possibleWords = wordsPool
            .Where(w => w.Length <= Math.Max(_options.GridWidth, _options.GridHeight))
            .ToList();

        // Keep trying to place words until we have enough or we run out of words to try
        while (HiddenWords.Count < _options.TotalWordsToHide && possibleWords.Count > 0)
        {
            // Pick a random word from the remaining possible words
            int index = _random.Next(possibleWords.Count);
            var word = possibleWords[index];

            // Attempt to place the selected word
            if (TryPlaceWord(word.ToUpper()))
            {
                HiddenWords.Add(word);
            }

            // Remove the word from the list so we don't try it again for this captcha
            possibleWords.RemoveAt(index);
        }

        // After trying, verify that we have at least the minimum required words
        if (HiddenWords.Count < _options.WordsRequiredToSolve)
        {
            throw new InvalidOperationException(
                "Could not fit the minimum required number of words into the grid. " +
                "Consider using a larger grid, shorter words, or requiring fewer words to solve.");
        }

        // Fill the rest of the grid with random letters
        FillEmptyCells();
    }

    private bool TryPlaceWord(string word)
    {
        // Try placing the word a few times before giving up
        for (int i = 0; i < 100; i++)
        {
            // Pick a random direction
            var (dX, dY) = _directions[_random.Next(_directions.Length)];

            // Pick a random starting point
            int startX = _random.Next(_options.GridWidth);
            int startY = _random.Next(_options.GridHeight);

            if (CanPlaceWordAt(word, startX, startY, dX, dY))
            {
                // Place the word if it fits
                for (int j = 0; j < word.Length; j++)
                {
                    _grid[startY + j * dY, startX + j * dX] = word[j];
                }
                return true;
            }
        }
        return false; // Failed to place the word
    }

    private bool CanPlaceWordAt(string word, int startX, int startY, int dX, int dY)
    {
        // Check if word goes out of bounds
        int endX = startX + (word.Length - 1) * dX;
        int endY = startY + (word.Length - 1) * dY;

        if (endX < 0 || endX >= _options.GridWidth || endY < 0 || endY >= _options.GridHeight)
        {
            return false;
        }

        // Check for conflicts with existing letters
        for (int i = 0; i < word.Length; i++)
        {
            char currentCell = _grid[startY + i * dY, startX + i * dX];
            // A cell is valid if it's empty ('\0') or contains the same character
            if (currentCell != '\0' && currentCell != word[i])
            {
                return false;
            }
        }
        return true;
    }

    private void FillEmptyCells()
    {
        for (int y = 0; y < _options.GridHeight; y++)
        {
            for (int x = 0; x < _options.GridWidth; x++)
            {
                if (_grid[y, x] == '\0')
                {
                    _grid[y, x] = (char)('A' + _random.Next(26));
                }
            }
        }
    }
}