namespace WordsCaptcha;

/// <summary>
/// Holds the configuration options for generating a word search captcha.
/// </summary>
public class WordSearchCaptchaOptions
{
    /// <summary>
    /// The width of the captcha grid.
    /// </summary>
    public int GridWidth { get; set; } = 10;

    /// <summary>
    /// The height of the captcha grid.
    /// </summary>
    public int GridHeight { get; set; } = 10;

    /// <summary>
    /// The total number of words to hide in the grid (N).
    /// </summary>
    public int TotalWordsToHide { get; set; } = 5;

    /// <summary>
    /// The minimum number of words a user must find to pass the captcha (M).
    /// </summary>
    public int WordsRequiredToSolve { get; set; } = 3;

    /// <summary>
    /// The list of possible words to choose from. Used only if WordsPoolFilePath is not set.
    /// </summary>
    public List<string> WordPool { get; set; } = [];

    /// <summary>
    /// The path to a text file containing words (one per line) to load into the word pool.
    /// </summary>
    public string? WordsPoolFilePath { get; set; }

    /// <summary>
    /// Should the generated captcha contain diagonal words?
    /// </summary>
    public bool IncludeDiagonal { get; set; } = true;

    /// <summary>
    /// Should the generated captcha contain words in reverse?
    /// </summary>
    public bool IncludeReverse { get; set; } = true;
}
