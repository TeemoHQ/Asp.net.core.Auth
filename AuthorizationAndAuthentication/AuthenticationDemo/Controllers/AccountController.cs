using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationDemo.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private UserStore _userStore;
        public AccountController(UserStore userStore)
        {
            _userStore = userStore;
        }


        [Authorize(AuthenticationSchemes = "OldAuthenticate")]
        [Route("old")]
        //[Authorize(Roles = "student")]
        [HttpPost]
        public async Task<string> Old()
        {
            return $"认证成功,claims:{JsonConvert.SerializeObject(HttpContext.User.Claims.Select(c => new string[] { c.Type, c.Value }))}";
        }

       // [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("bearercheck")]
        //[Authorize(Roles = "student")]
        [HttpPost]
        public async Task<string> test1()
        {
            return $"认证成功,claims:{JsonConvert.SerializeObject(HttpContext.User.Claims.Select(c => new string[] { c.Type, c.Value }))}";
        }

       // [Authorize(AuthenticationSchemes = "XueAnQuan")]
        // [Authorize(Policy = "XueAnQuan")]
        //[Authorize(Roles = "prv")]
        [Route("xueanquancheck")]
        [HttpPost]
        public async Task<string> test2()
        {
            return $"认证成功,claims:{JsonConvert.SerializeObject(HttpContext.User.Claims.Select(c => new string[] { c.Type, c.Value }))}";
        }

        [Route("/")]
        [HttpGet]
        public async Task Index()
        {
            await HttpContext.Response.WriteHtmlAsync(async res =>
            {
                await res.WriteAsync($"<h2>Hello Cookie Authentication</h2>");
                await res.WriteAsync("<a class=\"btn btn-default\" href=\"account/profile\">我的信息</a>");
            });
        }

        [Route("Profile")]
        [HttpGet]
        public async Task Profile()
        {
            await HttpContext.Response.WriteHtmlAsync(async res =>
            {
                await HttpContext.Response.WriteAsync($"<h1>你好，当前登录用户： {HttpResponseExtensions.HtmlEncode(HttpContext.User.Identity.Name)}</h1>");
                await HttpContext.Response.WriteAsync("<a class=\"btn btn-default\" href=\"/Account/Loginout\">退出</a>");
                await HttpContext.Response.WriteAsync($"<h2>AuthenticationType：{HttpContext.User.Identity.AuthenticationType}</h2>");
                await HttpContext.Response.WriteAsync("<h2>Claims:</h2>");
                await HttpContext.Response.WriteTableHeader(new string[] { "Claim Type", "Value" }, HttpContext.User.Claims.Select(c => new string[] { c.Type, c.Value }));
                var result = await HttpContext.AuthenticateAsync();
                await res.WriteAsync("<h2>Tokens:</h2>");
                await res.WriteTableHeader(new string[] { "Token Type", "Value" }, result.Properties.GetTokens().Select(token => new string[] { token.Name, token.Value }));
            });

        }

        /// <summary>
        /// 本地认证方式  局限性较大
        /// </summary>
        /// <returns></returns>
        #region cookies  

        [Route("Login")]
        [AllowAnonymous]
        [HttpGet]
        public async Task CookiesLoginGet()
        {
            await HttpContext.Response.WriteHtmlAsync(async res =>
            {
                await res.WriteAsync($"<form method=\"post\">");
                await res.WriteAsync($"<input type=\"hidden\" name=\"returnUrl\" value=\"{HttpResponseExtensions.HtmlEncode(HttpContext.Request.Query["ReturnUrl"])}\"/>");
                await res.WriteAsync($"<div class=\"form-group\"><label>用户名：<input type=\"text\" name=\"userName\" class=\"form-control\"></label></div>");
                await res.WriteAsync($"<div class=\"form-group\"><label>密码：<input type=\"password\" name=\"password\" class=\"form-control\"></label></div>");
                await res.WriteAsync($"<button type=\"submit\" class=\"btn btn-default\">登录</button>");
                await res.WriteAsync($"</form>");
            });

        }

        [Route("Login")]
        [AllowAnonymous]
        [HttpPost]
        public async Task CookiesLoginPost()
        {
            var user = _userStore.FindUser(HttpContext.Request.Form["userName"], HttpContext.Request.Form["password"]);
            if (user == null)
            {
                await HttpContext.Response.WriteHtmlAsync(async res =>
                {
                    await res.WriteAsync($"<h1>用户名或密码错误。</h1>");
                    await res.WriteAsync("<a class=\"btn btn-default\" href=\"/Account/Login\">返回</a>");
                });
            }
            else
            {
                /// <summary>
                /// 缺点：虽然claims设置的不多，但是cookies也会特别长，因为默认的claimtype用的url地址
                /// 解决办法：1.自定义成jwttype  2.利用SessionStore存储ticket，cookies里面只放一个Id（并没有很短）
                /// </summary>
                /// <returns></returns>
                var claimIdentity = new ClaimsIdentity("Cookie");
                claimIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
                claimIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Name));
                claimIdentity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
                claimIdentity.AddClaim(new Claim(ClaimTypes.MobilePhone, user.PhoneNumber));
                claimIdentity.AddClaim(new Claim(ClaimTypes.DateOfBirth, user.Birthday.ToString()));
                var claimsPrincipal = new ClaimsPrincipal(claimIdentity);


                //var claimIdentity = new ClaimsIdentity("Cookie", JwtClaimTypes.Name, JwtClaimTypes.Role);
                //claimIdentity.AddClaim(new Claim(JwtClaimTypes.Id, user.Id.ToString()));
                //claimIdentity.AddClaim(new Claim(JwtClaimTypes.Name, user.Name));
                //claimIdentity.AddClaim(new Claim(JwtClaimTypes.Email, user.Email));
                //claimIdentity.AddClaim(new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
                //claimIdentity.AddClaim(new Claim(JwtClaimTypes.BirthDate, user.Birthday.ToString()));


                // 在startup注册AddAuthentication时，指定了默认的Scheme，在这里便可以不再指定Scheme。
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    claimsPrincipal,
                    new AuthenticationProperties
                    {
                        // 持久保存 避免关闭浏览器后就清除
                        IsPersistent = true,
                        // 指定过期时间
                        ExpiresUtc = DateTime.UtcNow.AddMinutes(20)
                    });
                if (string.IsNullOrEmpty(HttpContext.Request.Form["ReturnUrl"]))
                {
                    HttpContext.Response.Redirect("/");
                }
                else
                {
                    HttpContext.Response.Redirect(HttpContext.Request.Form["ReturnUrl"]);
                }
            }
        }

        [Route("Loginout")]
        [HttpGet]
        [AllowAnonymous]
        public async Task CookiesLoginOut()
        {
            await HttpContext.SignOutAsync();
            HttpContext.Response.Redirect("/");
        }

        #endregion
    }
}
