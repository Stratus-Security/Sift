using SMBLibrary;
using Stratus.Sift.Connectors.Services;

namespace Stratus.Sift.Cli.Tests;

public sealed class SmbTransientRetryTests
{
    [Fact]
    public async Task InvalidSmbSessionSetup_RetriesWithFreshAttempt()
    {
        var attempts = 0;
        var result = await SmbTransientRetry.RunAsync(
            _ =>
            {
                attempts++;
                return attempts < 3
                    ? Task.FromException<int>(new SmbAuthenticationException(
                        "Kerberos", NTStatus.STATUS_INVALID_SMB, null, "No usable session response"))
                    : Task.FromResult(42);
            },
            "Opening SMB file",
            CancellationToken.None,
            _ => TimeSpan.Zero);

        Assert.Equal(42, result);
        Assert.Equal(3, attempts);
    }

    [Fact]
    public async Task ExhaustedTransientFailure_LeavesContentRetryable()
    {
        var attempts = 0;
        var exception = await Assert.ThrowsAsync<RemoteContentUnavailableException>(() =>
            SmbTransientRetry.RunAsync<int>(
                _ =>
                {
                    attempts++;
                    return Task.FromException<int>(new SmbOperationException(
                        NTStatus.STATUS_IO_TIMEOUT, "SMB response timed out"));
                },
                "Opening SMB file",
                CancellationToken.None,
                _ => TimeSpan.Zero));

        Assert.True(exception.ShouldRetry);
        Assert.Equal(4, attempts);
        Assert.IsType<SmbOperationException>(exception.InnerException);
    }

    [Fact]
    public async Task AccessDenied_DoesNotRetry()
    {
        var attempts = 0;
        await Assert.ThrowsAsync<SmbAuthenticationException>(() =>
            SmbTransientRetry.RunAsync<int>(
                _ =>
                {
                    attempts++;
                    return Task.FromException<int>(new SmbAuthenticationException(
                        "Kerberos", NTStatus.STATUS_ACCESS_DENIED, null, "Denied"));
                },
                "Opening SMB file",
                CancellationToken.None,
                _ => TimeSpan.Zero));

        Assert.Equal(1, attempts);
    }

    [Fact]
    public void ExplicitSspiFailure_IsNotTreatedAsAConnectionGlitch()
    {
        var exception = new SmbAuthenticationException(
            "Kerberos",
            NTStatus.STATUS_INVALID_SMB,
            unchecked((int)0x8009030C),
            "SSPI rejected the logon");

        Assert.False(SmbTransientRetry.IsTransient(exception));
    }
}
