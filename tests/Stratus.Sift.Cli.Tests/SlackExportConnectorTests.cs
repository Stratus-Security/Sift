using System.IO.Compression;
using System.Text;
using Stratus.Sift.Connectors.Interfaces;
using Stratus.Sift.Connectors.Slack;

namespace Stratus.Sift.Connectors.Tests;

public class SlackExportConnectorTests
{
    [Fact]
    public async Task Inspector_ReturnsOnlyHttpsSlackFileLinks()
    {
        using var export = SlackExportFixture.Create(new Dictionary<string, string>
        {
            ["workspace/channels.json"] = "[]",
            ["workspace/general/2026-07-14.json"] = """
                [{"files":[
                  {"id":"F1","name":"report.pdf","size":12,"mimetype":"application/pdf","url_private_download":"https://files.slack.com/files-pri/T1-F1/report.pdf"},
                  {"id":"F2","name":"evil.txt","url_private":"https://slack.com.evil.example/evil.txt"},
                  {"id":"F3","name":"insecure.txt","url_private":"http://files.slack.com/insecure.txt"}
                ]}]
                """
        });

        var references = await SlackExportInspector.GetFileReferencesAsync(export.ZipPath);

        var reference = Assert.Single(references);
        Assert.Equal("F1", reference.Id);
        Assert.Equal("report.pdf", reference.Name);
        Assert.Equal("files.slack.com", reference.DownloadUri.Host);
    }

    [Fact]
    public async Task Connector_TraversesWrappedExportAndNormalizesMessages()
    {
        using var export = SlackExportFixture.Create(new Dictionary<string, string>
        {
            ["workspace/channels.json"] = "[{\"id\":\"C1\",\"name\":\"general\"}]",
            ["workspace/users.json"] = "[{\"id\":\"U1\",\"name\":\"alice\"}]",
            ["workspace/general/2026-07-14.json"] = """
                [{"type":"message","user":"U1","ts":"1720915200.000001","text":"fallback secret","blocks":[{"type":"section","text":{"type":"mrkdwn","text":"block secret"}}],"files":[{"id":"F1","name":"credentials.txt","url_private":"https://files.slack.com/files-pri/T1-F1/credentials.txt"}]}]
                """
        });
        using var connector = new SlackExportConnector();
        await connector.InitializeAsync(new Dictionary<string, string> { ["Input"] = export.ZipPath });

        var drives = (await connector.GetDrivesAsync()).ToArray();

        Assert.Equal(2, drives.Length);
        var metadata = Assert.Single(drives, drive => drive.Name == "Workspace metadata");
        var conversation = Assert.Single(drives, drive => drive.Name == "general");
        Assert.Equal(2, (await metadata.GetChangesAsync(null)).Changes.Count());
        var message = Assert.Single((await conversation.GetChangesAsync(null)).Changes);
        var content = await ReadAsync(message);
        Assert.Contains("fallback secret", content);
        Assert.Contains("block secret", content);
        Assert.Contains("credentials.txt", content);
        Assert.Contains("files.slack.com", content);
    }

    [Fact]
    public async Task Connector_ScansSuppliedFilesAndInvalidConversationJson()
    {
        using var export = SlackExportFixture.Create(new Dictionary<string, string>
        {
            ["channels.json"] = "[]",
            ["general/broken.json"] = "client_secret = still-scan-this"
        });
        var suppliedFiles = Directory.CreateDirectory(Path.Combine(export.Root, "files"));
        await File.WriteAllTextAsync(Path.Combine(suppliedFiles.FullName, "evidence.txt"), "password = local-file-secret");
        using var connector = new SlackExportConnector();
        await connector.InitializeAsync(new Dictionary<string, string>
        {
            ["Input"] = export.ZipPath,
            ["FilesRoot"] = suppliedFiles.FullName
        });

        var drives = (await connector.GetDrivesAsync()).ToArray();
        var invalidJson = Assert.Single((await Assert.Single(drives, drive => drive.Name == "general").GetChangesAsync(null)).Changes);
        var localFile = Assert.Single((await Assert.Single(drives, drive => drive.Name == "Downloaded Slack files").GetChangesAsync(null)).Changes);

        Assert.Equal("client_secret = still-scan-this", await ReadAsync(invalidJson));
        Assert.Equal("password = local-file-secret", await ReadAsync(localFile));
    }

    private static async Task<string> ReadAsync(IRemoteFile file)
    {
        await using var stream = Assert.IsAssignableFrom<Stream>(await file.GetContentAsync());
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private sealed class SlackExportFixture : IDisposable
    {
        private SlackExportFixture(string root, string zipPath)
        {
            Root = root;
            ZipPath = zipPath;
        }

        internal string Root { get; }
        internal string ZipPath { get; }

        internal static SlackExportFixture Create(IReadOnlyDictionary<string, string> entries)
        {
            var root = Path.Combine(Path.GetTempPath(), "StratusSnareTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var zipPath = Path.Combine(root, "slack-export.zip");
            using var stream = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Create);
            foreach (var item in entries)
            {
                var entry = archive.CreateEntry(item.Key);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                writer.Write(item.Value);
            }

            return new SlackExportFixture(root, zipPath);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }
}
