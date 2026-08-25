namespace Stratus.Sift.Connectors.Interfaces;

/// <summary>
/// Supplies an opaque, stable identity for the authenticated principal used by a connector.
/// The value must not contain a credential or directly identifying account value.
/// </summary>
public interface IConnectorCheckpointScopeProvider
{
    string CheckpointScope { get; }
}
