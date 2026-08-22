using Stratus.Sift.Core;

namespace Stratus.Sift.Cli;

public static class Program
{
    public static Task<int> Main(string[] args)
        => RunAsync(args, Console.Out, Console.Error, CancellationToken.None);

    internal static async Task<int> RunAsync(
        IReadOnlyList<string> args,
        TextWriter standardOutput,
        TextWriter standardError,
        CancellationToken cancellationToken)
    {
        var parsed = CliArguments.Parse(args);
        if (parsed.ShowHelp)
        {
            await standardOutput.WriteLineAsync(CliArguments.HelpText);
            return ExitCodes.Success;
        }

        if (parsed.ShowVersion)
        {
            await standardOutput.WriteLineAsync(OutputWriter.Version);
            return ExitCodes.Success;
        }

        if (parsed.Error is not null)
        {
            await standardError.WriteLineAsync(parsed.Error);
            await standardError.WriteLineAsync("Run 'sift --help' for usage.");
            return ExitCodes.InvalidArguments;
        }

        using var cancellationSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        ConsoleCancelEventHandler? cancelHandler = null;
        if (!Console.IsInputRedirected)
        {
            cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellationSource.Cancel();
            };
            Console.CancelKeyPress += cancelHandler;
        }

        try
        {
            var options = parsed.Options!;
            PlatformGuard.EnsureSupported(options.Path);
            var result = await new SiftFileScanner().ScanAsync(
                options.Path,
                new SiftFileScanOptions(
                    options.EnumerateOnly,
                    options.IncludeBinary,
                    options.Recurse,
                    options.Parallelism,
                    options.MaximumFileSizeBytes,
                    options.Extensions,
                    options.ExcludedDirectoryNames),
                cancellationSource.Token);
            await OutputWriter.WriteAsync(result, options, standardOutput, cancellationSource.Token);
            return result.Errors.Count == 0 ? ExitCodes.Success : ExitCodes.Partial;
        }
        catch (OperationCanceledException) when (cancellationSource.IsCancellationRequested)
        {
            await standardError.WriteLineAsync("Scan cancelled.");
            return ExitCodes.Cancelled;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException)
        {
            await standardError.WriteLineAsync(exception.Message);
            return ExitCodes.Failed;
        }
        finally
        {
            if (cancelHandler is not null)
            {
                Console.CancelKeyPress -= cancelHandler;
            }
        }
    }
}

internal static class ExitCodes
{
    internal const int Success = 0;
    internal const int InvalidArguments = 2;
    internal const int Failed = 3;
    internal const int Partial = 4;
    internal const int Cancelled = 130;
}
