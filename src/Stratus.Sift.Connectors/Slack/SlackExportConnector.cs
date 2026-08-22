using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Core;

namespace Stratus.Sift.Connectors.Slack;

public sealed class SlackExportConnector : IConnector, IDisposable
{
    private SlackExportSource? _source;
    private string? _filesRoot;

    public string ProviderName => CommonConstants.ConnectorProviders.SlackExport;

    public Task InitializeAsync(Dictionary<string, string> configuration, CancellationToken cancellationToken = default)
    {
        var input = configuration.GetValueOrDefault("Input");
        if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("Slack export input is required.");
        _source?.Dispose();
        _source = SlackExportSource.Open(input);
        _filesRoot = null;

        var filesRoot = configuration.GetValueOrDefault("FilesRoot");
        if (!string.IsNullOrWhiteSpace(filesRoot))
        {
            _filesRoot = Path.GetFullPath(filesRoot);
            if (!Directory.Exists(_filesRoot)) throw new ArgumentException($"Slack files directory '{filesRoot}' was not found.");
        }

        return Task.CompletedTask;
    }

    public Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default)
    {
        if (_source == null) throw new InvalidOperationException("Slack export connector has not been initialized.");
        var drives = new List<IRemoteDrive>();
        var rootJson = _source.Entries.Where(path => !path.Contains('/') && path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (rootJson.Length > 0) drives.Add(SlackExportDrive.ForMetadata(_source, rootJson));

        foreach (var group in _source.Entries
                     .Where(path => path.Contains('/') && path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                     .GroupBy(path => path[..path.IndexOf('/')], StringComparer.OrdinalIgnoreCase)
                     .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase))
        {
            drives.Add(SlackExportDrive.ForConversation(_source, group.Key, group.ToArray()));
        }

        if (_filesRoot != null) drives.Add(SlackExportDrive.ForFiles(_source.DisplayName, _filesRoot));
        if (drives.Count == 0) throw new InvalidDataException("The input does not contain recognizable Slack export JSON or supplied files.");
        return Task.FromResult<IEnumerable<IRemoteDrive>>(drives);
    }

    public void Dispose() => _source?.Dispose();
}
