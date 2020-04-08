using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationDemo.Self
{
    public class CustomAuthenticationSchemeOptions: AuthenticationSchemeOptions
    {
        public SelfParseToIdentity SelfParseToIdentity { get; set; }
    }
    public delegate Task<ClaimsIdentity> SelfParseToIdentity(HttpContext httpContext);
}
