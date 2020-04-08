using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationDemo
{
    /// <summary>
    /// 如果用了  [Authorize]  那么用不到这个方法
    /// </summary>
    public static class MyAppBuilderExtensions
    {
        // 模拟授权实现  
        public static IApplicationBuilder UseAuthorize(this IApplicationBuilder app)
        {
            return app.Use(async (context, next) =>
            {
                if (context.Request.Path == "/")
                {
                    await next();
                }
                else
                {
                    if (context.User?.Identity?.IsAuthenticated ?? false)
                    {
                        await next();
                    }
                    else
                    {
                        //手动触发Authorize  可以代替 Action 上的 [Authorize] 这个标记
                        await context.ChallengeAsync();
                    }
                }
            });
        }
    }
}
