using Azure.Core;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Azure.Identity.Federation;

public class GithubActionsTokenCredential : TokenCredential
{
    private const string ActionsRequestTokenKey = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
    private const string ActionsRequestUrlKey = "ACTIONS_ID_TOKEN_REQUEST_URL";
    private const string DefaultIdTokenAudience = "api://AzureADTokenExchange";

    private const string AzureTenantIdKey = "AZURE_TENANT_ID";
    private const string AzureClientIdKey = "AZURE_CLIENT_ID";

    private readonly string? _requestToken;
    private readonly string? _requestUrl;
    private readonly string IdTokenAudience;
    private readonly string TenantId;
    private readonly string ClientId;
    private readonly HttpClient httpClient;
    private ClientAssertionCredential? clientAssertionCredential;

    public GithubActionsTokenCredential(string? tenantId = null, string? clientId = null, string? idTokenAudience = DefaultIdTokenAudience, HttpClient? httpClient = null)
    {
        IdTokenAudience = idTokenAudience ?? DefaultIdTokenAudience;
        _requestToken = Environment.GetEnvironmentVariable(ActionsRequestTokenKey);
        _requestUrl = Environment.GetEnvironmentVariable(ActionsRequestUrlKey);
        this.httpClient = httpClient ?? new HttpClient();
        this.httpClient.DefaultRequestHeaders.UserAgent.Clear();
        this.httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Azure.Identity.Federation", "1.0"));
        // Not sure if this is needed, see https://github.com/actions/toolkit/blob/c5c786523e095ca3fabfc4d345e16242da34e108/packages/core/src/oidc-utils.ts#L22
        this.httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("actions/oidc-client", "1.0"));
        TenantId = tenantId ?? Environment.GetEnvironmentVariable(AzureTenantIdKey);
        ClientId = clientId ?? Environment.GetEnvironmentVariable(AzureClientIdKey);
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        ValidateSettings();
        clientAssertionCredential ??= new ClientAssertionCredential(TenantId, ClientId, (cancallationToken) => GetIdToken(cancellationToken));

        return clientAssertionCredential.GetToken(requestContext, cancellationToken);
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        ValidateSettings();
        clientAssertionCredential ??= new ClientAssertionCredential(TenantId, ClientId, (cancallationToken) => GetIdToken(cancellationToken));
        return clientAssertionCredential.GetTokenAsync(requestContext, cancellationToken);
    }

    private void ValidateSettings()
    {
        if (string.IsNullOrWhiteSpace(_requestToken) || string.IsNullOrWhiteSpace(_requestUrl) || !Uri.TryCreate(_requestUrl, UriKind.Absolute, out _))
        {
            throw new CredentialUnavailableException($"Environment variables '{ActionsRequestTokenKey}' and/or '{ActionsRequestUrlKey}' are not set.");
        }

        if (string.IsNullOrWhiteSpace(IdTokenAudience))
        {
            throw new ArgumentException("Audience must be set.", nameof(IdTokenAudience));
        }

        if (string.IsNullOrWhiteSpace(TenantId))
        {
            throw new ArgumentException("Tenant ID must be set", nameof(TenantId));
        }

        if (string.IsNullOrWhiteSpace(ClientId))
        {
            throw new ArgumentException("Client ID must be set", nameof(ClientId));
        }
    }

    private async Task<string> GetIdToken(CancellationToken cancellationToken)
    {
        var uri = new Uri($"{_requestUrl!}&audience={System.Web.HttpUtility.UrlEncode(IdTokenAudience!)}");
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _requestToken!);
        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new CredentialUnavailableException($"Request to '{uri}' failed with status code '{response.StatusCode}'.");
        var result = await response.Content.ReadFromJsonAsync<GithubTokenResponse>(cancellationToken: cancellationToken).ConfigureAwait(false);

        return result!.value;
    }
}

public class GithubTokenResponse
{
    public string value { get; set; }
}
