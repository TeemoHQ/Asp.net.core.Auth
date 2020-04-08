using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationDemo.Core
{
    public class SelfPolicyEvaluator : PolicyEvaluator
    {
        private readonly IAuthorizationService _authorization;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="authorization">The authorization service.</param>
        public SelfPolicyEvaluator(IAuthorizationService authorization) : base(authorization)
        {
            _authorization = authorization;
        }

        /// <summary>
        /// Does authentication for <see cref="AuthorizationPolicy.AuthenticationSchemes"/> and sets the resulting
        /// <see cref="ClaimsPrincipal"/> to <see cref="HttpContext.User"/>.  If no schemes are set, this is a no-op.
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns><see cref="AuthenticateResult.Success"/> unless all schemes specified by <see cref="AuthorizationPolicy.AuthenticationSchemes"/> failed to authenticate.  </returns>
        public override async Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
        {
            if (policy.AuthenticationSchemes != null && policy.AuthenticationSchemes.Count > 0)
            {
            }
            //    ClaimsPrincipal newPrincipal = null;
            //    foreach (var scheme in policy.AuthenticationSchemes)
            //    {
            //        var result = await context.AuthenticateAsync(scheme);
            //        if (result != null && result.Succeeded)
            //        {
            //            newPrincipal = SecurityHelper.MergeUserPrincipal(newPrincipal, result.Principal);
            //        }
            //    }

            //    if (newPrincipal != null)
            //    {
            //        context.User = newPrincipal;
            //        return AuthenticateResult.Success(new AuthenticationTicket(newPrincipal, string.Join(";", policy.AuthenticationSchemes)));
            //    }
            //    else
            //    {
            //        context.User = new ClaimsPrincipal(new ClaimsIdentity());
            //        return AuthenticateResult.NoResult();
            //    }
            //}

            //return (context.User?.Identity?.IsAuthenticated ?? false)
            //    ? AuthenticateResult.Success(new AuthenticationTicket(context.User, "context.User"))
            //    : AuthenticateResult.NoResult();

            return await base.AuthenticateAsync(policy, context);

        }

    }
}
