using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServerDemo
{
    public class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new List<ApiResource>
            {
                new ApiResource("cseeapp","cseeapp"),
                new ApiResource("usercenter", "用户中心"),
                new ApiResource("parentshelper","安全教育app-api")
            };
        }


        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {


                new Client
                {
                    ClientId = "oauth.code",
                    ClientName = "Server-based Client (Code)",

                    RedirectUris = { "http://localhost:5001/signin-oauth" },
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-oauth" },

                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "profile", "email", "api" },
                    AllowOfflineAccess = true
                },
                new Client
                {
                    ClientId = "oidc.hybrid",
                    ClientName = "Server-based Client (Hybrid)",

                    RedirectUris = { "http://localhost:5002/signin-oidc" },
                    FrontChannelLogoutUri = "http://localhost:5002/signout-oidc",
                    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },

                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Hybrid,
                    AllowedScopes = { "openid", "profile", "email", "api" },
                    AllowOfflineAccess = true,
                    AllowAccessTokensViaBrowser = true
                },
                //new Client
                //{
                //    ClientId = "jwt.implicit",
                //    ClientName = "Implicit Client (Web)",
                //    AllowedGrantTypes = GrantTypes.Implicit,
                //    AllowAccessTokensViaBrowser = true,

                //    //AccessTokenLifetime = 70,

                //    RedirectUris = { "http://localhost:5200/callback" },
                //    PostLogoutRedirectUris = { "http://localhost:5200/home" },
                //    AllowedCorsOrigins = { "http://localhost:5200" },

                //    AllowedScopes = { "openid", "profile", "email", "api" },
                //},
                //new Client
                //{
                //    ClientId = "client.cc",
                //    AllowedGrantTypes = GrantTypes.ClientCredentials,
                //    ClientSecrets =
                //    {
                //        new Secret("secret".Sha256())
                //    },
                //    AllowedScopes = { "api" }
                //},
                new Client
                {
                    ClientId = "app_anquan",
                    AllowedGrantTypes =GrantTypes.ResourceOwnerPassword,
                    AllowOfflineAccess = true,
                    AccessTokenLifetime = 24*60*60 , //1天
                    AbsoluteRefreshTokenLifetime = 24*60*60, //15天
                    ClientSecrets =
                    {
                        new Secret("shc%hD#2!shG&".Sha256())
                    },
                    RequireClientSecret = false,
                    AllowedScopes = GetALLScopes(),
                    IncludeJwtId = true,
                    UpdateAccessTokenClaimsOnRefresh = true
                }
            };
        }
        public static List<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("cseeapp","cseeapp"),
                new ApiResource("usercenter", "用户中心"),
                new ApiResource("parentshelper","安全教育app-api")
            };
        }
        public static ICollection<string> GetALLScopes()
        {
            var apis = new List<string>();
            GetApiResources().ToList().ForEach(x => apis.Add(x.Name));
            apis.Add(IdentityServerConstants.StandardScopes.OfflineAccess);
            apis.Add(IdentityServerConstants.StandardScopes.OpenId);
            apis.Add(IdentityServerConstants.StandardScopes.Profile);

            return apis;
        }
    }
}
