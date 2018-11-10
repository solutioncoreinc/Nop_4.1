using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace Nop.Plugin.Api.IdentityServer
{
    public class ConfigureIdentityServer
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Email(),
                new IdentityResources.Profile(),
                new IdentityResources.Phone(),
                new IdentityResources.Address(),
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("nopapi", "Nopcommerce REST Api")
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "NopAndroid",
                    ClientName = "NopAndroid",
                    AllowedGrantTypes = GrantTypes.Hybrid,
                    ClientSecrets = {
                        new Secret("secret".Sha256())
                    },
                    RedirectUris = { "xamarinformsclients://callback"}, // after login
                    RequireConsent = false,
                    RequirePkce = true,
                    PostLogoutRedirectUris = { "http://localhost:56134/signout-callback-oidc"}, // after logout
                    AllowedCorsOrigins = { "http://localhost:56134" },
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "nopapi"
                    },
                    AllowOfflineAccess = true,
                    AllowAccessTokensViaBrowser = true,                    
                }
            };
        }
    }
}
