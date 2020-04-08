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

            //�ͻ�����֤
            services.AddAuthentication(options =>
            {
                //��ֻ��Ҫcookies
                //options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                //��cookies��OAuth����  ��ʵֻ��һ����Ȩ����  Զ����֤
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OAuthDefaults.DisplayName;

                //��cookies��OIDC����   ��Ȩ���̼��������֤��token���������ݵ�Ԫ����֤ͨ����ӵ���identity�� Զ����֤
                //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

                //����jwt��֤  ������identityserver��֤�ͻ���AccessTokenValidation����ȻҲ����ֱ����Microsoft.AspNetCore.Authentication.JwtBearer���ڲ�ʵ�ֲ��
                //options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

                //��scheme jwt��֤
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.ClaimsIssuer = "Cookie";
                //o.SessionStore ����cookies��� Id
                //o.LoginPath   ���û�δ��¼ʱ���ض��򵽸�·����Ĭ�ϣ�/Account/Login
                //o.LogoutPath  ָ���ǳ���·����Ĭ�ϣ�/Account/Logout
                //o.AccessDeniedPath  ���û���Ȩ����ʱ���ض��򵽸�·����Ĭ�ϣ�/Account/AccessDenied
                //o.ExpireTimeSpan ָ��Cookie�Ĺ���ʱ��
                //o.Events = new CookieAuthenticationEvents
                //{
                //    //���������û���Ϣ�������֤ʧ�ܻ��������µ�cookies
                //    //��������֤ͨ�����ѯ���ݿ⣬��Ľϴ󣬿���ͨ��������֤�������������
                //    //OnValidatePrincipal = LastChangedValidator.ValidateAsync
                //};
            })
            .AddOAuth(OAuthDefaults.DisplayName, options =>
            {
                options.ClientId = "oauth.code";
                options.ClientSecret = "secret";
                options.AuthorizationEndpoint = "http://localhost:4000/connect/authorize";//ȥ��ȡԶ��code
                options.TokenEndpoint = "http://localhost:4000/connect/token";
                options.CallbackPath = "/signin-oauth";//����code����ȡaccesstoken
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.SaveTokens = true;
                // �¼�ִ��˳�� ��
                // 1.����Ticket֮ǰ����
                options.Events.OnCreatingTicket = context => Task.CompletedTask;
                // 2.����Ticketʧ��ʱ����
                options.Events.OnRemoteFailure = context => Task.CompletedTask;
                // 3.Ticket�������֮�󴥷�
                options.Events.OnTicketReceived = context => Task.CompletedTask;
                // 4.Challengeʱ������Ĭ����ת��OAuth������
                // options.Events.OnRedirectToAuthorizationEndpoint = context => context.Response.Redirect(context.RedirectUri);
            })
            .AddOpenIdConnect(o =>
            {
                o.ClientId = "oidc.hybrid";
                o.ClientSecret = "secret";

                // ��������Authority���ͱ���ָ��MetadataAddress
                o.Authority = "http://localhost:4000/";
                // Ĭ��ΪAuthority+".well-known/openid-configuration"
                //o.MetadataAddress = "http://localhost:4000";
                o.RequireHttpsMetadata = false;

                // ʹ�û����
                o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                // �Ƿ�Tokens���浽AuthenticationProperties��
                o.SaveTokens = true;
                // �Ƿ��UserInfoEndpoint��ȡClaims
                o.GetClaimsFromUserInfoEndpoint = true;
                // �ڱ�ʾ���У�ʹ�õ���IdentityServer��������ClaimTypeʹ�õ���JwtClaimTypes��
                o.TokenValidationParameters.NameClaimType = "name"; //JwtClaimTypes.Name;

                // ���²������ж�Ӧ��Ĭ��ֵ��ͨ���������á�
                //o.CallbackPath = new PathString("/signin-oidc");
                //o.SignedOutCallbackPath = new PathString("/signout-callback-oidc");
                //o.RemoteSignOutPath = new PathString("/signout-oidc");
                //o.Scope.Add("openid");
                //o.Scope.Add("profile");
                //o.ResponseMode = OpenIdConnectResponseMode.FormPost; 

                /***********************************����¼�***********************************/
                // δ��Ȩʱ���ض���OIDC������ʱ����
                //o.Events.OnRedirectToIdentityProvider = context => Task.CompletedTask;

                // ��ȡ����Ȩ��ʱ����
                //o.Events.OnAuthorizationCodeReceived = context => Task.CompletedTask;
                // ���յ�OIDC���������ص���֤��Ϣ������Code, ID Token�ȣ�ʱ����
                //o.Events.OnMessageReceived = context => Task.CompletedTask;
                // ���յ�TokenEndpoint���ص���Ϣʱ����
                //o.Events.OnTokenResponseReceived = context => Task.CompletedTask;
                // ��֤Tokenʱ����
                //o.Events.OnTokenValidated = context => Task.CompletedTask;
                // ���յ�UserInfoEndpoint���ص���Ϣʱ����
                //o.Events.OnUserInformationReceived = context => Task.CompletedTask;
                // �����쳣ʱ����
                //o.Events.OnAuthenticationFailed = context => Task.CompletedTask;

                // �˳�ʱ���ض���OIDC������ʱ����
                //o.Events.OnRedirectToIdentityProviderForSignOut = context => Task.CompletedTask;
                // OIDC�������˳��󣬷���˻ص�ʱ����
                //o.Events.OnRemoteSignOut = context => Task.CompletedTask;
                // OIDC�������˳��󣬿ͻ����ض���ʱ����
                //o.Events.OnSignedOutCallbackRedirect = context => Task.CompletedTask;

            })
            .AddIdentityServerAuthentication(JwtBearerDefaults.AuthenticationScheme, options =>
             {
                 options.SupportedTokens = SupportedTokens.Jwt;
                 options.Authority = "http://appapi-dev.safetree.com.cn/usercenter";
                 options.RequireHttpsMetadata = false;
                 options.ApiName = "usercenter";//�����identityserver���õ�һ��
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
                 options.ApiName = "usercenter";//�����identityserver���õ�һ��
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
                     return new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Name, "����"), new Claim(ClaimTypes.Role, "�ְ�") });
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

            //        /***********************************TokenValidationParameters�Ĳ���Ĭ��ֵ***********************************/
            //        // RequireSignedTokens = true,
            //        // SaveSigninToken = false,
            //        // ValidateActor = false,
            //        // ������������������Ϊfalse�����Բ���֤Issuer��Audience�����ǲ�������������
            //        // ValidateAudience = true,
            //        // ValidateIssuer = true, 
            //        // ValidateIssuerSigningKey = false,
            //        // �Ƿ�Ҫ��Token��Claims�б������Expires
            //        // RequireExpirationTime = true,
            //        // ����ķ�����ʱ��ƫ����
            //        // ClockSkew = TimeSpan.FromSeconds(300),
            //        // �Ƿ���֤Token��Ч�ڣ�ʹ�õ�ǰʱ����Token��Claims�е�NotBefore��Expires�Ա�
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
           

            //�ͻ�����Ȩ
            services.AddAuthorization(options =>
            {
                //����scheme ��֤��ʽ 
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
