using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Validator
{
    public class MyTokenValidator : ISecurityTokenValidator
    {
        public bool CanValidateToken { get; }
        public int MaximumTokenSizeInBytes { get; set; }

        public bool CanReadToken(string securityToken)
        {
            return true;
        }

        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters,
            out SecurityToken validatedToken)
        {
            validatedToken = null;
            var identity = new ClaimsIdentity(JwtBearerDefaults.AuthenticationScheme);
            if (securityToken == "123456")
            {
                identity.AddClaims(new List<Claim>
                {
                    new Claim(ClaimTypes.Name,"HQ"),
                    new Claim(ClaimTypes.Role,"admin")
                });
            }
            var principal=new ClaimsPrincipal(identity);
            return principal;
        }


    }
}
