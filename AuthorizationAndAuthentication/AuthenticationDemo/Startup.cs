using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthenticationDemo.Core;
using AuthenticationDemo.Self;
using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace AuthenticationDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthenticationDemo", Version = "v1" });
                options.OperationFilter<AssignOperationVendorExtensions>();
                var openApiSecurityScheme = new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                };
                options.AddSecurityDefinition("Bearer", openApiSecurityScheme);
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {openApiSecurityScheme, new List<string>()}
                });
            });
            services.AddSingleton<UserStore>();

            //客户端认证
            services.AddAuthentication(options =>
            {
                //当只需要cookies
                //options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                //当cookies和OAuth共存  其实只是一个授权流程  远程认证
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OAuthDefaults.DisplayName;

                //当cookies和OIDC共存   授权流程加上身份认证（token里面加了身份单元，认证通过后加到了identity） 远程认证
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

                //单个jwt认证  这里走identityserver认证客户端AccessTokenValidation，当然也可以直接用Microsoft.AspNetCore.Authentication.JwtBearer，内部实现差不多
                //options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

                //多scheme jwt认证
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.ClaimsIssuer = "Cookie";
                //o.SessionStore 用于cookies变短 Id
                //o.LoginPath   当用户未登录时，重定向到该路径，默认：/Account/Login
                //o.LogoutPath  指定登出的路径，默认：/Account/Logout
                //o.AccessDeniedPath  当用户无权访问时，重定向到该路径，默认：/Account/AccessDenied
                //o.ExpireTimeSpan 指定Cookie的过期时间
                //o.Events = new CookieAuthenticationEvents
                //{
                //    //可以用于用户信息变更后，验证失败或者生成新的cookies
                //    //不过该验证通常会查询数据库，损耗较大，可以通过设置验证周期来提高性能
                //    //OnValidatePrincipal = LastChangedValidator.ValidateAsync
                //};
            })
            .AddOAuth(OAuthDefaults.DisplayName, options =>
            {
                options.ClientId = "oauth.code";
                options.ClientSecret = "secret";
                options.AuthorizationEndpoint = "http://localhost:4000/connect/authorize";//去获取远端code
                options.TokenEndpoint = "http://localhost:4000/connect/token";
                options.CallbackPath = "/signin-oauth";//消费code，获取accesstoken
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.SaveTokens = true;
                // 事件执行顺序 ：
                // 1.创建Ticket之前触发
                options.Events.OnCreatingTicket = context => Task.CompletedTask;
                // 2.创建Ticket失败时触发
                options.Events.OnRemoteFailure = context => Task.CompletedTask;
                // 3.Ticket接收完成之后触发
                options.Events.OnTicketReceived = context => Task.CompletedTask;
                // 4.Challenge时触发，默认跳转到OAuth服务器
                // options.Events.OnRedirectToAuthorizationEndpoint = context => context.Response.Redirect(context.RedirectUri);
            })
            .AddOpenIdConnect(o =>
            {
                o.ClientId = "oidc.hybrid";
                o.ClientSecret = "secret";

                // 若不设置Authority，就必须指定MetadataAddress
                o.Authority = "http://localhost:4000/";
                // 默认为Authority+".well-known/openid-configuration"
                //o.MetadataAddress = "http://localhost:4000";
                o.RequireHttpsMetadata = false;

                // 使用混合流
                o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                // 是否将Tokens保存到AuthenticationProperties中
                o.SaveTokens = true;
                // 是否从UserInfoEndpoint获取Claims
                o.GetClaimsFromUserInfoEndpoint = true;
                // 在本示例中，使用的是IdentityServer，而它的ClaimType使用的是JwtClaimTypes。
                o.TokenValidationParameters.NameClaimType = "name"; //JwtClaimTypes.Name;

                // 以下参数均有对应的默认值，通常无需设置。
                //o.CallbackPath = new PathString("/signin-oidc");
                //o.SignedOutCallbackPath = new PathString("/signout-callback-oidc");
                //o.RemoteSignOutPath = new PathString("/signout-oidc");
                //o.Scope.Add("openid");
                //o.Scope.Add("profile");
                //o.ResponseMode = OpenIdConnectResponseMode.FormPost; 

                /***********************************相关事件***********************************/
                // 未授权时，重定向到OIDC服务器时触发
                //o.Events.OnRedirectToIdentityProvider = context => Task.CompletedTask;

                // 获取到授权码时触发
                //o.Events.OnAuthorizationCodeReceived = context => Task.CompletedTask;
                // 接收到OIDC服务器返回的认证信息（包含Code, ID Token等）时触发
                //o.Events.OnMessageReceived = context => Task.CompletedTask;
                // 接收到TokenEndpoint返回的信息时触发
                //o.Events.OnTokenResponseReceived = context => Task.CompletedTask;
                // 验证Token时触发
                //o.Events.OnTokenValidated = context => Task.CompletedTask;
                // 接收到UserInfoEndpoint返回的信息时触发
                //o.Events.OnUserInformationReceived = context => Task.CompletedTask;
                // 出现异常时触发
                //o.Events.OnAuthenticationFailed = context => Task.CompletedTask;

                // 退出时，重定向到OIDC服务器时触发
                //o.Events.OnRedirectToIdentityProviderForSignOut = context => Task.CompletedTask;
                // OIDC服务器退出后，服务端回调时触发
                //o.Events.OnRemoteSignOut = context => Task.CompletedTask;
                // OIDC服务器退出后，客户端重定向时触发
                //o.Events.OnSignedOutCallbackRedirect = context => Task.CompletedTask;

            })
            .AddIdentityServerAuthentication(JwtBearerDefaults.AuthenticationScheme, options =>
             {
                 options.SupportedTokens = SupportedTokens.Jwt;
                 options.Authority = "http://appapi-dev.safetree.com.cn/usercenter";
                 options.RequireHttpsMetadata = false;
                 options.ApiName = "usercenter";//必须和identityserver设置的一致
                 options.RoleClaimType = ClaimTypes.Role;
                 options.JwtBearerEvents = new JwtBearerEvents
                 {
                     OnTokenValidated = async context =>
                     {
                         var currentIdentity = ((ClaimsIdentity)context.Principal.Identity);
                     }
                 };
             })
            .AddIdentityServerAuthentication("XueAnQuan", options =>
             {
                 options.SupportedTokens = SupportedTokens.Jwt;
                 options.Authority = "http://appapi-dev.safetree.com.cn/usercenter";
                 options.RequireHttpsMetadata = false;
                 options.ApiName = "usercenter";//必须和identityserver设置的一致
                 options.RoleClaimType = ClaimTypes.Role;
                 options.TokenRetriever = TokenRetrieval.FromAuthorizationHeader("XueAnQuan");
                 options.JwtBearerEvents = new JwtBearerEvents
                 {
                     OnTokenValidated = async context =>
                     {
                         var currentIdentity = ((ClaimsIdentity)context.Principal.Identity);
                     }
                 };
             })
            .AddScheme<CustomAuthenticationSchemeOptions, CustomAuthenticationHandler>("OldAuthenticate", (s) =>
             {
                 s.SelfParseToIdentity = async context =>
                 {
                     return new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Name, "张三"), new Claim(ClaimTypes.Role, "爸爸") });
                 };
             });
            //.AddJwtBearer(o =>
            //{
            //    o.Authority = "http://127.0.0.1:4000";
            //    o.Audience = "api";
            //    o.RequireHttpsMetadata = false;

            //    o.Events = new JwtBearerEvents()
            //    {
            //        OnMessageReceived = context =>
            //        {
            //            context.Token = context.Request.Query["access_token"];
            //            return Task.CompletedTask;
            //        },
            //        OnTokenValidated = async context =>
            //        {
            //            var currentIdentity = ((ClaimsIdentity)context.Principal.Identity);
            //            await Task.CompletedTask;
            //        }
            //    };
            //    o.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        NameClaimType = JwtClaimTypes.Name,
            //        RoleClaimType = JwtClaimTypes.Role,

            //        ValidIssuer = "http://localhost:4000",
            //        ValidAudience = "api",
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("JwtBearerSample_11231~#$%#%^2235"))

            //        /***********************************TokenValidationParameters的参数默认值***********************************/
            //        // RequireSignedTokens = true,
            //        // SaveSigninToken = false,
            //        // ValidateActor = false,
            //        // 将下面两个参数设置为false，可以不验证Issuer和Audience，但是不建议这样做。
            //        // ValidateAudience = true,
            //        // ValidateIssuer = true, 
            //        // ValidateIssuerSigningKey = false,
            //        // 是否要求Token的Claims中必须包含Expires
            //        // RequireExpirationTime = true,
            //        // 允许的服务器时间偏移量
            //        // ClockSkew = TimeSpan.FromSeconds(300),
            //        // 是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
            //        // ValidateLifetime = true
            //    };
            //})

            // .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o =>
            // {
            //     o.Authority = "http://appapi-dev.safetree.com.cn/usercenter";
            //     o.Audience = "usercenter";
            //     o.RequireHttpsMetadata = false;

            //     o.Events = new JwtBearerEvents()
            //     {
            //         OnMessageReceived = context =>
            //         {
            //             context.Token = context.Request.Query["access_token"];
            //             return Task.CompletedTask;
            //         },
            //         OnTokenValidated = async context =>
            //         {
            //             var currentIdentity = ((ClaimsIdentity)context.Principal.Identity);
            //             await Task.CompletedTask;
            //         }
            //     };
            // })
           

            //客户端授权
            services.AddAuthorization(options =>
            {
                //增加scheme 认证方式 
                var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme, "XueAnQuan", "OldAuthenticate");
                defaultAuthorizationPolicyBuilder = defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
                options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();

                //options.DefaultPolicy = new AuthorizationPolicyBuilder()
                //.RequireAuthenticatedUser()
                //.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, "XueAnQuan")
                //.Build();

                //options.AddPolicy("XueAnQuan", new AuthorizationPolicyBuilder()
                //   .RequireAuthenticatedUser()
                //   .AddAuthenticationSchemes("XueAnQuan")
                //   .Build());

            });

        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseRouting();
            app.UseAuthentication();

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("v1/swagger.json", "My API V1");
            });


        }
    }
}
