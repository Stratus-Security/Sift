# Third-party notices

Stratus Sift uses the following third-party packages. Copyright and licence terms remain with their respective owners.

| Package or project | Licence |
| --- | --- |
| .NET runtime and Microsoft.Extensions libraries | MIT |
| Azure.Identity | MIT |
| DocumentFormat.OpenXml | MIT |
| ExcelDataReader | MIT |
| SharpCompress and ZstdSharp.Port | MIT |
| Microsoft Graph SDK and Microsoft Kiota | MIT |
| Microsoft.Playwright | Apache-2.0 |
| OfficeIMO.Core, OfficeIMO.Word, OfficeIMO.Excel, OfficeIMO.PowerPoint, and OfficeIMO.OneNote | MIT |
| OpenMcdf | MIT |
| PdfPig | Apache-2.0 |
| SMBLibrary | LGPL-3.0 |
| System.CommandLine | MIT |
| System.DirectoryServices.Protocols and System.IO.FileSystem.AccessControl | MIT |

Test projects also use Microsoft.NET.Test.Sdk, xUnit, xunit.runner.visualstudio, and coverlet.collector under their respective licences. The dependency versions used for each release are recorded in the repository lock files and release SBOM.

The legacy PowerPoint test fixture is from Apache POI under Apache-2.0; its source, licence, and notices are recorded in `tests/Stratus.Sift.Cli.Tests/Fixtures/LegacyOffice`.

The XLSB, RAR, and 7z interoperability fixtures are from ExcelDataReader and SharpCompress under MIT; pinned source references and licence copies are recorded in `tests/Stratus.Sift.Cli.Tests/Fixtures/Coverage`.
