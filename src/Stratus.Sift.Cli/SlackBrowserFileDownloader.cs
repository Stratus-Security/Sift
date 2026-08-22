using Microsoft.Playwright;
using Stratus.Sift.Connectors.Slack;

namespace Stratus.Sift.Cli;

internal static class SlackBrowserFileDownloader
{
    internal static async Task<SlackBrowserDownloadSession> DownloadAsync(
        string exportPath,
        string browserChannel,
        CancellationToken cancellationToken = default)
    {
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException("Browser-assisted Slack downloads require an interactive terminal.");
        }

        var references = await SlackExportInspector.GetFileReferencesAsync(exportPath, cancellationToken);
        var session = SlackBrowserDownloadSession.Create();
        if (references.Count == 0)
        {
            Console.WriteLine("The Slack export contains no downloadable Slack file links.");
            return session;
        }

        try
        {
            using var playwright = await Playwright.CreateAsync();
            await using var context = await playwright.Chromium.LaunchPersistentContextAsync(session.BrowserProfileDirectory, new BrowserTypeLaunchPersistentContextOptions
            {
                Channel = browserChannel.ToLowerInvariant(),
                Headless = false,
                AcceptDownloads = true,
                DownloadsPath = session.BrowserDownloadsDirectory
            });
            var page = context.Pages.FirstOrDefault() ?? await context.NewPageAsync();
            await page.GotoAsync("https://app.slack.com/client", new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = 60_000
            });

            Console.WriteLine();
            Console.WriteLine("An isolated browser window has opened. Sign in to the Slack workspace that produced the export, complete MFA, then return here.");
            Console.Write("Press Enter when Slack is fully open (or type 'cancel' to stop): ");
            var response = Console.ReadLine();
            if (string.Equals(response?.Trim(), "cancel", StringComparison.OrdinalIgnoreCase))
            {
                throw new OperationCanceledException("Browser-assisted Slack download was canceled.");
            }

            var completed = 0;
            var failed = 0;
            foreach (var reference in references)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var waitForDownload = page.WaitForDownloadAsync(new PageWaitForDownloadOptions { Timeout = 60_000 });
                    try
                    {
                        await page.GotoAsync(reference.DownloadUri.AbsoluteUri, new PageGotoOptions
                        {
                            WaitUntil = WaitUntilState.Commit,
                            Timeout = 60_000
                        });
                    }
                    catch (PlaywrightException ex) when (ex.Message.Contains("Download is starting", StringComparison.OrdinalIgnoreCase))
                    {
                    }

                    var download = await waitForDownload;
                    var fileName = BuildSafeFileName(reference.Id, download.SuggestedFilename, reference.Name);
                    await download.SaveAsAsync(Path.Combine(session.DownloadDirectory, fileName));
                    completed++;
                    Console.Write($"\rDownloaded {completed:N0}/{references.Count:N0} Slack files ({failed:N0} failed)...");
                }
                catch (Exception ex) when (ex is PlaywrightException or TimeoutException)
                {
                    failed++;
                    Console.WriteLine($"\nWarning: could not download Slack file '{reference.Name}': {ex.Message}");
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Browser download complete: {completed:N0} downloaded, {failed:N0} failed. The isolated browser session is now closed.");
            return session;
        }
        catch
        {
            await session.DisposeAsync();
            throw;
        }
    }

    private static string BuildSafeFileName(string id, string? suggestedName, string fallbackName)
    {
        var rawName = string.IsNullOrWhiteSpace(suggestedName) ? fallbackName : suggestedName;
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        var safeName = string.Concat(rawName.Select(ch => invalid.Contains(ch) || ch is '/' or '\\' ? '_' : ch)).Trim();
        if (string.IsNullOrWhiteSpace(safeName)) safeName = "slack-file";
        if (safeName.Length > 150)
        {
            var extension = Path.GetExtension(safeName);
            safeName = safeName[..Math.Min(140, safeName.Length)] + extension;
        }

        var safeId = string.Concat(id.Where(char.IsLetterOrDigit));
        if (safeId.Length > 40) safeId = safeId[..40];
        return $"{safeId}__{safeName}";
    }
}

internal sealed class SlackBrowserDownloadSession : IAsyncDisposable
{
    private readonly string _rootDirectory;

    private SlackBrowserDownloadSession(string rootDirectory)
    {
        _rootDirectory = rootDirectory;
        DownloadDirectory = Path.Combine(rootDirectory, "files");
        BrowserDownloadsDirectory = Path.Combine(rootDirectory, "browser-downloads");
        BrowserProfileDirectory = Path.Combine(rootDirectory, "browser-profile");
        Directory.CreateDirectory(DownloadDirectory);
        Directory.CreateDirectory(BrowserDownloadsDirectory);
        Directory.CreateDirectory(BrowserProfileDirectory);
    }

    internal string DownloadDirectory { get; }
    internal string BrowserDownloadsDirectory { get; }
    internal string BrowserProfileDirectory { get; }

    internal static SlackBrowserDownloadSession Create()
    {
        var root = Path.Combine(Path.GetTempPath(), "StratusSift", "slack-browser", Guid.NewGuid().ToString("N"));
        return new SlackBrowserDownloadSession(root);
    }

    public async ValueTask DisposeAsync()
    {
        var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "StratusSift", "slack-browser"))
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var resolved = Path.GetFullPath(_rootDirectory);
        if (!resolved.StartsWith(expectedRoot, StringComparison.OrdinalIgnoreCase)) return;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                if (Directory.Exists(resolved)) Directory.Delete(resolved, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 2)
            {
                await Task.Delay(200 * (attempt + 1));
            }
            catch (UnauthorizedAccessException) when (attempt < 2)
            {
                await Task.Delay(200 * (attempt + 1));
            }
        }
    }
}
