namespace Stratus.Sift.Core.Validation;

public static class ContentExtensionProfiles
{
    public const string SourceAndConfig = "SourceAndConfig";

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> Profiles =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [SourceAndConfig] = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                string.Empty,
                ".ascx", ".ashx", ".asmx", ".asp", ".aspx",
                ".bash_history", ".bashrc", ".bat", ".bicep", ".bicepparam", ".c", ".cc", ".cfm", ".cjs", ".cmd",
                ".cnf", ".conf", ".config", ".cpp", ".credentials", ".cs", ".cshtml", ".csv", ".cue", ".cxx",
                ".dart", ".dist", ".do", ".dockerfile", ".dockerignore", ".docx",
                ".editorconfig", ".env", ".es", ".es6", ".exports", ".extra",
                ".fdb", ".fs", ".fsx", ".functions",
                ".gemrc", ".git-credentials", ".gitconfig", ".go", ".gql", ".gradle", ".graphql", ".groovy",
                ".h", ".har", ".hcl", ".hpp", ".hta", ".http",
                ".inc", ".inf", ".ini", ".irb_history",
                ".ipynb", ".java", ".js", ".json", ".jsonl", ".jsp", ".jsx",
                ".key", ".kt", ".kts", ".log", ".ls", ".lua",
                ".markdown", ".md", ".mdc", ".mjs",
                ".ndjson", ".netrc", ".nix", ".npmrc", ".nuget", ".pdf", ".pem", ".php", ".php3", ".php5", ".php7",
                ".phtml", ".pl", ".profile", ".prompt", ".prompty", ".properties", ".ps1", ".psd1", ".psm1",
                ".pub", ".py", ".pypirc",
                ".proto", ".r", ".rb", ".rc", ".rego", ".rest", ".rs",
                ".scala", ".service", ".sh", ".sh_history", ".sql", ".sqlite", ".sqlite3", ".svelte", ".swift",
                ".targets", ".templ", ".tf", ".tfplan", ".tfrc", ".tfstate", ".tfvars", ".toml", ".ts", ".tsv", ".tsx", ".txt",
                ".vb", ".vbe", ".vbs", ".vue", ".wsc", ".wsf",
                ".xlsx", ".xml", ".yaml", ".yml", ".zsh_history", ".zshrc"
            }
        };

    public static IReadOnlyCollection<string> Names { get; } = Profiles.Keys.ToArray();

    public static bool IsKnown(string? profileName)
        => string.IsNullOrWhiteSpace(profileName) || Profiles.ContainsKey(profileName.Trim());

    public static IReadOnlySet<string> Resolve(string? profileName)
    {
        if (string.IsNullOrWhiteSpace(profileName))
        {
            return Empty;
        }

        return Profiles.TryGetValue(profileName.Trim(), out var extensions)
            ? extensions
            : Empty;
    }

    private static IReadOnlySet<string> Empty { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}
