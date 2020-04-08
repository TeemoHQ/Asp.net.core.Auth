using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
namespace AuthenticationDemo
{
    /// <summary>
    /// swagger 操作扩展
    /// </summary>
    public class AssignOperationVendorExtensions : IOperationFilter
    {
        private static readonly Regex AuthorRegex = new Regex("<author>([^<]+)</author>");

        /// <summary>
        /// 添加应用
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="context"></param>
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            // 游客注释
            var attributes = context.MethodInfo.GetCustomAttributes(true);
            var isAnonymous = attributes.Any(attribute => typeof(AllowAnonymousAttribute) == attribute.GetType());
            operation.Summary = $"【{ (isAnonymous ? "游客" : "登录") }:√】 {operation.Summary}";

            if (!isAnonymous)
            {
                operation.Responses.TryAdd("401", new OpenApiResponse
                {
                    Description = "Unauthorized"
                });
                operation.Responses.TryAdd("403", new OpenApiResponse
                {
                    Description = "Forbidden"
                });
            }

            // 作者注释
            if (!string.IsNullOrWhiteSpace(operation.Summary))
            {
                var matched = AuthorRegex.Match(operation.Summary);
                if (matched.Success)
                {
                    operation.Summary = operation.Summary.Replace(matched.Groups[0].Value, $"【作者: {matched.Groups[1].Value}】");
                }
            }

            operation.Parameters ??= new List<OpenApiParameter>();
        }
    }
}
