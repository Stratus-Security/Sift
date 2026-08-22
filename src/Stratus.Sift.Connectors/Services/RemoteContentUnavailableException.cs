namespace Stratus.Sift.Connectors.Services;

public sealed class RemoteContentUnavailableException : Exception
{
    public RemoteContentUnavailableException(string message, bool shouldRetry, int? statusCode = null, Exception? innerException = null)
        : base(message, innerException)
    {
        ShouldRetry = shouldRetry;
        StatusCode = statusCode;
    }

    public bool ShouldRetry { get; }

    public int? StatusCode { get; }
}
