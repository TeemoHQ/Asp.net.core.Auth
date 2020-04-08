using Microsoft.AspNetCore.Authentication.Cookies;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationDemo.Core
{
    public static class LastChangedValidator
    {
        public static async Task ValidateAsync(CookieValidatePrincipalContext context)
        {
            //var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
            //var userPrincipal = context.Principal;
            //string lastChanged = (from c in userPrincipal.Claims where c.Type == "LastUpdated" select c.Value).FirstOrDefault();
            //if (string.IsNullOrEmpty(lastChanged) || !userRepository.ValidateLastChanged(userPrincipal, lastChanged))
            //{

            //}
            // 1. 验证失败 等同于 Principal = principal;
            context.RejectPrincipal();

            // 2. 验证通过，并会重新生成Cookie。
            context.ShouldRenew = true;
        }
    }
}
