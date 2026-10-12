namespace Stratus.Sift.Connectors.Interfaces;

/// <summary>Reports folders that could not be enumerated while allowing other folders to be visited.</summary>
public interface IRemoteDriveEnumerationReportProvider
{
    long EnumerationFailureCount { get; }

    /// <summary>A bounded set of diagnostic samples, including an unexpected failure when one occurred.</summary>
    IReadOnlyList<RemoteDriveEnumerationFailure> EnumerationFailures { get; }
}

public sealed record RemoteDriveEnumerationFailure(string Path, Exception Exception);
