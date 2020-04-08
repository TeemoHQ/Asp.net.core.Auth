using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AuthenticationDemo.Self
{
    public class CustomAuthenticationHandler : AuthenticationHandler<CustomAuthenticationSchemeOptions>
    {
        private CustomAuthenticationSchemeOptions _options;
        public CustomAuthenticationHandler(IOptionsMonitor<CustomAuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _options = options.Get("OldAuthenticate");
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                var identity = await _options.SelfParseToIdentity(Request.HttpContext).ConfigureAwait(false);
                if (identity != null && identity.Claims != null && identity.Claims.ToList().Count > 0)
                {
                    var newIdentity = new ClaimsIdentity(identity.Claims, "OldAuthenticate");
                    var res = AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(newIdentity), Scheme.Name));
                    return res;
                }
                return AuthenticateResult.Fail("Unauthorized");
            }
            catch (Exception ex)
            {
                //todo log
                return AuthenticateResult.Fail("Unauthorized");
            }
        }

        /// <summary>
        /// 未登录时的处理
        /// </summary>
        /// <param name="properties"></param>
        /// <returns></returns>
        public Task ChallengeAsync(AuthenticationProperties properties)
        {
            Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            return Task.CompletedTask;
        }

        /// <summary>
        /// 权限不足时的处理
        /// </summary>
        /// <param name="properties"></param>
        /// <returns></returns>
        public Task ForbidAsync(AuthenticationProperties properties)
        {
            Context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            return Task.CompletedTask;
        }
    }
}
