# Contributing

Bug reports and focused pull requests are welcome. Open an issue before starting a large change so the approach can be agreed first.

Keep changes limited to Sift, include tests where practical and run the following commands before opening a pull request:

```powershell
dotnet restore .\Stratus.Sift.slnx --locked-mode
dotnet build .\Stratus.Sift.slnx --configuration Release --no-restore
dotnet test .\Stratus.Sift.slnx --configuration Release --no-build
```

By contributing, you confirm that you have the right to submit the work under the repository's AGPL-3.0-only licence.
