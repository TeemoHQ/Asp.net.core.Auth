// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using AccessTokenValidation4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    /// <summary>
    /// Authentication handler for validating both JWT and reference tokens
    /// </summary>
    public class SelfIdentityServerAuthenticationHandler : AuthenticationHandler<SelfIdentityServerAuthenticationOptions>
    {
        private readonly ILogger _logger;
        /// <inheritdoc />
        public SelfIdentityServerAuthenticationHandler(
            IOptionsMonitor<SelfIdentityServerAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            _logger = logger.CreateLogger<SelfIdentityServerAuthenticationHandler>();
        }

        /// <summary>
        /// Tries to validate a token on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            _logger.LogTrace("HandleAuthenticateAsync called");
            string token = null;
            string authorization = Context.Request.Headers["Authorization"];
            if (!string.IsNullOrWhiteSpace(authorization))
            {
                if (authorization.StartsWith($"{IdentityServerAuthenticationDefaults.AuthenticationScheme} ", StringComparison.OrdinalIgnoreCase))
                {
                    token = authorization.Substring(IdentityServerAuthenticationDefaults.AuthenticationScheme.Length + 1).Trim();
                }
                if (authorization.StartsWith($"{IdentityServerAuthenticationDefaults.XueAnQuanScheme} ", StringComparison.OrdinalIgnoreCase))
                {
                    token = authorization.Substring($"{IdentityServerAuthenticationDefaults.XueAnQuanScheme}".Length + 1).Trim();
                }
            }
            var jwtScheme = Scheme.Name + IdentityServerAuthenticationDefaults.JwtAuthenticationScheme;
            var introspectionScheme = Scheme.Name + IdentityServerAuthenticationDefaults.IntrospectionAuthenticationScheme;

            bool removeToken = false;

            try
            {
                if (token != null)
                {
                    _logger.LogTrace("Token found: {token}", token);

                    removeToken = true;
                    Context.Items.Add(IdentityServerAuthenticationDefaults.TokenItemsKey, token);

                    // seems to be a JWT
                    if (token.Contains('.') && Options.SupportsJwt)
                    {
                        _logger.LogTrace("Token is a JWT and is supported.");


                        Context.Items.Add(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, jwtScheme);

                        return await Context.AuthenticateAsync(jwtScheme);
                    }
                    else if (Options.SupportsIntrospection)
                    {
                        _logger.LogTrace("Token is a reference token and is supported.");

                        Context.Items.Add(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, introspectionScheme);
                        return await Context.AuthenticateAsync(introspectionScheme);
                    }
                    else
                    {
                        _logger.LogTrace("Neither JWT nor reference tokens seem to be correctly configured for incoming token.");
                    }
                }
                else
                {
                    if (Options?.TryConvert2ClaimsIdentity != null)
                    {
                        // find token in default location
                        if (!OldAuthentication.JwtTokenValidate(Context, Options?.TryConvert2ClaimsIdentity))
                        {
                            if (!OldAuthentication.AccessTokenValidate(Context, Options?.TryConvert2ClaimsIdentity))
                            {
                                if (OldAuthentication.CookieValidate(Context, Options?.TryConvert2ClaimsIdentity))
                                {
                                    return AuthenticateResult.Success(new AuthenticationTicket(Context.User, Scheme.Name));
                                }
                            }
                            else
                            {
                                return AuthenticateResult.Success(new AuthenticationTicket(Context.User, Scheme.Name));
                            }
                        }
                        else
                        {
                            return AuthenticateResult.Success(new AuthenticationTicket(Context.User, Scheme.Name));
                        }
                    }
                    if (Options?.SelfParseToIdentity != null)
                    {
                        if (!await OldAuthentication.SelfParse(Context, Options?.SelfParseToIdentity).ConfigureAwait(false))
                        {
                            return AuthenticateResult.Success(new AuthenticationTicket(Context.User, Scheme.Name));
                        }
                    }
                }

                // set the default challenge handler to JwtBearer if supported
                if (Options.SupportsJwt)
                {
                    Context.Items.Add(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, jwtScheme);
                }

                return AuthenticateResult.NoResult();
            }
            finally
            {
                if (removeToken)
                {
                    Context.Items.Remove(IdentityServerAuthenticationDefaults.TokenItemsKey);
                }
            }
        }

        /// <summary>
        /// Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        /// deals an authentication interaction as part of it's request flow. (like adding a response header, or
        /// changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <param name="properties"></param>
        /// <returns>
        /// A Task.
        /// </returns>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (Context.Items.TryGetValue(IdentityServerAuthenticationDefaults.EffectiveSchemeKey + Scheme.Name, out object value))
            {
                if (value is string scheme)
                {
                    _logger.LogTrace("Forwarding challenge to scheme: {scheme}", scheme);
                    await Context.ChallengeAsync(scheme);
                }
            }
            else
            {
                await base.HandleChallengeAsync(properties);
            }
        }

    }
}