using Azure.Core;
using Azure.Identity;

namespace Stratus.Sift.Connectors.SharePoint;

// The inner credential must have DisableAutomaticAuthentication=true. Only this
// wrapper can open sign-in, and expanding data permissions requires explicit opt-in.
internal sealed class Microsoft365DelegatedCredential(TokenCredential silent,
    Func<TokenRequestContext, CancellationToken, Task> authenticate,
    string[]? loginScopes, bool requestAdditionalPermissions) : TokenCredential
{
    private readonly SemaphoreSlim _authentication = new(1);
    private readonly HashSet<string> _denied = new(StringComparer.Ordinal);
    private volatile bool _signedIn;

    public override AccessToken GetToken(TokenRequestContext context, CancellationToken ct)
        => GetTokenAsync(context, ct).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken ct)
    {
        try
        {
            var token = await silent.GetTokenAsync(context, ct);
            _signedIn = true;
            return token;
        }
        catch (AuthenticationRequiredException) { }
        await _authentication.WaitAsync(ct);
        try
        {
            try
            {
                var token = await silent.GetTokenAsync(context, ct);
                _signedIn = true;
                return token;
            }
            catch (AuthenticationRequiredException) { }
            if (!_signedIn)
            {
                await authenticate(loginScopes == null ? context : new TokenRequestContext(loginScopes), ct);
                _signedIn = true;
                try { return await silent.GetTokenAsync(context, ct); }
                catch (AuthenticationRequiredException) { }
            }
            var key = string.Join(" ", context.Scopes.Order(StringComparer.Ordinal));
            if (!requestAdditionalPermissions || !_denied.Add(key))
                throw new Microsoft365ConsentRequiredException();
            await authenticate(context, ct);
            return await silent.GetTokenAsync(context, ct);
        }
        finally { _authentication.Release(); }
    }
}

internal sealed class Microsoft365ConsentRequiredException()
    : UnauthorizedAccessException("Additional consent is required. RequestAdditionalPermissions=true allows requesting it; existing-access scans do not open a consent prompt.");
