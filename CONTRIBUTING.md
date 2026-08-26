# Contributing

Bug reports and focused pull requests are welcome. Open an issue before starting a large change so the approach can be agreed first if it's not clear.
PLEASE check your work if it was done by an AI.

Keep changes limited to Sift, include tests where practical and run the following commands before opening a pull request:

```powershell
dotnet restore .\Stratus.Sift.slnx --locked-mode
dotnet build .\Stratus.Sift.slnx --configuration Release --no-restore
dotnet test .\Stratus.Sift.slnx --configuration Release --no-build
```

By contributing, you confirm that you have the right to submit the work under the repository's AGPL-3.0-only licence.

## How to add a connector
To add a connector, simply add a folder under src/Status.Sift.Connectors for the service, keep all your code in there and implement the interfaces: IConnector, IConnectorDiscoveryReportProvider, IConnectorCheckpointScopeProvider.

Keep all code for that connector in the single folder and everyone will be happy... probably.