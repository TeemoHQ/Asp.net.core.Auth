using IdentityServer4.AccessTokenValidation;
using Jose;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AccessTokenValidation4
{
    public class OldAuthentication
    {
        public static bool AccessTokenValidate(HttpContext context, TryConvert2ClaimsIdentity tryConvert2ClaimsIdentity)
        {
            var url = context.Request.Path.ToString();
            if (url.Contains("access_token"))
            {
                var accessToken = context.Request.Query["access_token"];
                if (!string.IsNullOrEmpty(accessToken))
                {
                    tryConvert2ClaimsIdentity(CustomAuthorizationScheme.GUID, accessToken, out var identity);
                    if (identity != null)
                    {
                        context.User = new ClaimsPrincipal(identity);
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool JwtTokenValidate(HttpContext context, TryConvert2ClaimsIdentity tryConvert2ClaimsIdentity)
        {
            string authorization = context.Request.Headers["Authorization"];
            if (!string.IsNullOrEmpty(authorization) && authorization.Contains(".") &&
                authorization.StartsWith("User ", StringComparison.OrdinalIgnoreCase))
            {
                var tokenValue = authorization.Substring("User ".Length).Trim();
                var jwtHeader = JWT.Headers(tokenValue);
                if ((jwtHeader["alg"] == null || !jwtHeader["alg"].Equals("RSA1_5")) ||
                    (jwtHeader["enc"] == null || !jwtHeader["enc"].Equals("A256GCM")))
                {
                    return false;
                }
                tryConvert2ClaimsIdentity(CustomAuthorizationScheme.User, tokenValue, out var identity);
                if (identity != null)
                {
                    context.User = new ClaimsPrincipal(identity);
                    return true;
                }
            }
            return false;
        }

        public static bool CookieValidate(HttpContext context, TryConvert2ClaimsIdentity tryConvert2ClaimsIdentity)
        {
            var userId = context.Request.Cookies["UserID"];
            if (!string.IsNullOrWhiteSpace(userId))
            {
                tryConvert2ClaimsIdentity(CustomAuthorizationScheme.Cookie, userId, out var identity);
                if (identity != null)
                {
                    context.User = new ClaimsPrincipal(identity);
                    return true;
                }
            }
            return false;
        }

        public static async Task<bool> SelfParse(HttpContext context, SelfParseToIdentity selfParseToIdentity)
        {
            var identity = await selfParseToIdentity(context).ConfigureAwait(false);
            if (identity != null && identity.Claims != null && identity.Claims.ToList().Count > 0)
            {
                context.User = new ClaimsPrincipal(identity);
                return true;
            }
            return false;
        }
    }
}
