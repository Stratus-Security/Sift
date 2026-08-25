namespace Stratus.Sift.Connectors.Services;

public sealed class RemoteContentUnavailableException : Exception
{
    public RemoteContentUnavailableException(
        string message,
        bool shouldRetry,
        int? statusCode = null,
        Exception? innerException = null)
        : this(message, shouldRetry, false, statusCode, innerException)
    {
    }

    public RemoteContentUnavailableException(
        string message,
        bool shouldRetry,
        bool isExpected,
        int? statusCode = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        ShouldRetry = shouldRetry;
        StatusCode = statusCode;
        IsExpected = isExpected;
    }

    public bool ShouldRetry { get; }

    public int? StatusCode { get; }

    public bool IsExpected { get; }
}
