namespace Stratus.Sift.Connectors.Interfaces;

public interface IConnector
{
    string ProviderName { get; } // e.g., "SharePoint", "Dropbox"
    
    Task InitializeAsync(Dictionary<string, string> configuration, CancellationToken cancellationToken = default);
    Task<IEnumerable<IRemoteDrive>> GetDrivesAsync(CancellationToken cancellationToken = default);
}
