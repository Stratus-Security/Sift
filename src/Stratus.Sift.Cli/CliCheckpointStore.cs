using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Stratus.Sift.Cli;

/// <summary>
/// Persists only scanner continuation tokens under source- and credential-scoped opaque keys.
/// It deliberately contains no credentials, agent identity, enrolment, tenant, command, or
/// management state.
/// </summary>
internal sealed class CliCheckpointStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly Dictionary<string, string> _remoteDriveTokens;
    private readonly ILogger<CliCheckpointStore> _logger;
    private readonly string _filePath;
    private readonly object _sync = new();

    public CliCheckpointStore(
        IConfiguration configuration,
        ILogger<CliCheckpointStore> logger)
    {
        _logger = logger;
        _filePath = configuration["ContentScanner:CheckpointPath"]
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Stratus",
                "ContentScanner",
                "checkpoints.json");
        _remoteDriveTokens = Load();
    }

    public string? GetRemoteDriveToken(string driveId)
    {
        lock (_sync)
        {
            return _remoteDriveTokens.TryGetValue(driveId, out var token) ? token : null;
        }
    }

    public void SetRemoteDriveToken(string driveId, string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(driveId);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        lock (_sync)
        {
            _remoteDriveTokens[driveId] = token;
            Save();
        }
    }

    public void ClearRemoteDriveToken(string driveId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(driveId);

        lock (_sync)
        {
            if (_remoteDriveTokens.Remove(driveId))
            {
                Save();
            }
        }
    }

    private Dictionary<string, string> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                return new Dictionary<string, string>(StringComparer.Ordinal);
            }

            var state = JsonSerializer.Deserialize(
                File.ReadAllText(_filePath),
                CliJsonContext.Default.CliCheckpointState);
            return new Dictionary<string, string>(
                state?.RemoteDriveTokens ?? new Dictionary<string, string>(),
                StringComparer.Ordinal);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not read scanner checkpoints from {Path}", _filePath);
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private void Save()
    {
        try
        {
            var directory = Path.GetDirectoryName(_filePath)
                ?? throw new InvalidOperationException("The checkpoint path has no parent directory.");
            Directory.CreateDirectory(directory);

            var temporaryPath = _filePath + ".tmp";
            var state = new CliCheckpointState(new Dictionary<string, string>(_remoteDriveTokens));
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(state, CliJsonContext.Default.CliCheckpointState));

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    temporaryPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(temporaryPath, _filePath, overwrite: true);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not persist scanner checkpoints to {Path}", _filePath);
        }
    }

}

internal sealed record CliCheckpointState(Dictionary<string, string> RemoteDriveTokens);
