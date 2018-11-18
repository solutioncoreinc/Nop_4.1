using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Nop.Services.Customers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Nop.Plugin.Api.IdentityServer
{
    public class UserProfileService : IProfileService
    {
        protected readonly ICustomerService _customerService;

        public UserProfileService(ICustomerService customerService)
        {
            _customerService = customerService;
        }

        public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            if (context.RequestedClaimTypes.Any())
            {
                var user = _customerService.GetCustomerByUsername(context.Subject.GetSubjectId());

                if (user != null)
                {
                    context.AddRequestedClaims(
                        new List<Claim>
                        {
                            new Claim(ClaimTypes.Email, user.Email),
                            new Claim(ClaimTypes.Name, user.Username),
                            new Claim("api", "nopapi")
                        });
                }
            }

            return Task.CompletedTask;
        }

        public virtual Task IsActiveAsync(IsActiveContext context)
        {
            var user = _customerService.GetCustomerByUsername(context.Subject.GetSubjectId());
            context.IsActive = user.Active;

            return Task.CompletedTask;
        }
    }
}
