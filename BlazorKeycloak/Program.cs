using System.Security.Claims;
using BlazorKeycloak.Components;
using Keycloak.AuthServices.Authentication;
using Keycloak.AuthServices.Authorization;
using Keycloak.AuthServices.Sdk.Admin;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace BlazorKeycloak
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddCookie(cookie =>
                {
                    cookie.Cookie.MaxAge = TimeSpan.FromMinutes(1);
                    cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    cookie.Cookie.SameSite = SameSiteMode.Lax;
                    cookie.SlidingExpiration = true;
                })
                .AddOpenIdConnect(options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.Authority =
                        $"{builder.Configuration["Keycloak:auth-server-url"]}realms/{builder.Configuration["Keycloak:realm"]}";
                    options.ClientId = builder.Configuration["Keycloak:resource"];
                    options.ClientSecret = builder.Configuration["Keycloak:credentials:secret"];
                    options.MetadataAddress =
                        $"{builder.Configuration["Keycloak:auth-server-url"]}realms/{builder.Configuration["Keycloak:realm"]}" +
                        "/.well-known/openid-configuration";
                    options.RequireHttpsMetadata = false;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.SaveTokens = true;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = ClaimTypes.Role,
                        ValidateIssuer = true
                    };
                });

            builder.Services.AddAuthorization(o =>
                {
                    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                })
                .AddKeycloakAuthorization(builder.Configuration);

            builder.Services.AddKeycloakAdminHttpClient(builder.Configuration);

            // Add services to the container.
            builder.Services.AddRazorComponents().AddInteractiveServerComponents();


            builder.Services.AddSingleton<IAuthorizationPolicyProvider, ProtectedResourcePolicyProvider>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseAntiforgery();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            app.Run();
        }
    }
}