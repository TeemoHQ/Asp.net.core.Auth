using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class SelfIdentityServerAuthenticationOptions: IdentityServerAuthenticationOptions
    {
        [Obsolete]
        public TryConvert2ClaimsIdentity TryConvert2ClaimsIdentity { get; set; }

        public SelfParseToIdentity SelfParseToIdentity { get; set; }
    }

    public delegate Task<ClaimsIdentity> SelfParseToIdentity(HttpContext httpContext);

    /// <summary>
    /// 身份信息工厂
    /// </summary>
    /// <param name="scheme">身份认证类型</param>
    /// <param name="authentication">身份认证token</param>
    /// <param name="identity">认证成功后返回的身份信息</param>
    public delegate bool TryConvert2ClaimsIdentity(CustomAuthorizationScheme scheme,
        string authentication,
        out ClaimsIdentity identity);
    public enum CustomAuthorizationScheme
    {
        [Description("老版本jwtToken验证方式")]
        User = 1,

        [Description("GUID形式的的accessToken")]
        GUID = 2,

        [Description("Html5页面cookie验证")]
        Cookie = 3,
    }
}
