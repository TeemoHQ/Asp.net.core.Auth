using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Jwt.Models;
using Jwt.ViewModel;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Controllers
{
    [Route("[controller]/[action]")]
    public class AuthorizeController : Controller
    {
        private JwtSettings _jwtSettings;

        public AuthorizeController(IOptions<JwtSettings> OpJs)
        {
            _jwtSettings = OpJs.Value;
        }

        [HttpPost]
        public IActionResult Token([FromBody]LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {
                //database acthentication
                if (loginViewModel.UserName == "HQ" && loginViewModel.Password == "123456")
                {
                    //create token
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name,"HQ"),
                        new Claim(ClaimTypes.Role,"admin")
                    };
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    var token = new JwtSecurityToken(
                       issuer: _jwtSettings.Issuer,
                       audience: _jwtSettings.Audience,
                       claims: claims,
                       notBefore: DateTime.Now,
                       expires: DateTime.Now.AddMinutes(30),
                       signingCredentials: creds);

                    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                }
            }
            return BadRequest();
        }
    }
}
