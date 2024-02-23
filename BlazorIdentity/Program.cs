using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

namespace BlazorIdentity
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("#app");
            builder.RootComponents.Add<HeadOutlet>("head::after");

            builder.Services.AddHttpClient("api", client => client.BaseAddress = new Uri(builder.Configuration["Api:Url"]))
                .AddHttpMessageHandler(sp => sp.GetRequiredService<AuthorizationMessageHandler>()
                    .ConfigureHandler(authorizedUrls: new[] { builder.Configuration["Api:Url"] }));

            builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("api"));

            builder.Services.AddOidcAuthentication<RemoteAuthenticationState, KeycloakRemoteUserAccount>(options =>
            {
                builder.Configuration.Bind("ProviderOptions", options.ProviderOptions);
                builder.Configuration.Bind("UserOptions", options.UserOptions);
            }).AddAccountClaimsPrincipalFactory<RemoteAuthenticationState, KeycloakRemoteUserAccount, KeycloakAccountClaimsPrincipalFactory>();

            await builder.Build().RunAsync();
        }
    }

    public class KeycloakRemoteUserAccount : RemoteUserAccount
    {
        [JsonPropertyName("roles")]
        public string[]? Roles { get; set; }

        [JsonPropertyName("groups")]

        public string[]? Groups { get; set; }
    }

    public class KeycloakAccountClaimsPrincipalFactory : AccountClaimsPrincipalFactory<KeycloakRemoteUserAccount>
    {
        
        public KeycloakAccountClaimsPrincipalFactory(NavigationManager navigation,
            IAccessTokenProviderAccessor accessor) : base(accessor)
        {
        }

        public override async ValueTask<ClaimsPrincipal> CreateUserAsync(
            KeycloakRemoteUserAccount account, RemoteAuthenticationUserOptions options)
        {
            var initialUser = await base.CreateUserAsync(account, options);

            if (initialUser.Identity != null && initialUser.Identity.IsAuthenticated)
            {
                var userIdentity = (ClaimsIdentity)initialUser.Identity;

                if (account.Roles is not null)
                {
                    foreach (var value in account.Roles)
                    {
                        userIdentity.AddClaim(new Claim("roles", value));
                    }
                }
            }

            return initialUser;
        }

    }
}
