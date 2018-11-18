namespace Nop.Plugin.Api.Controllers.Odata
{
    using IdentityServer4.Events;
    using IdentityServer4.Models;
    using IdentityServer4.Services;
    using IdentityServer4.Stores;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Nop.Plugin.Api.Constants;
    using Nop.Plugin.Api.Controllers.Account;
    using Nop.Plugin.Api.Models.Account;
    using Nop.Services.Customers;
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;

    public class AccountController : Controller
    {
        private readonly AccountService _account;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly ICustomerRegistrationService _customerRegistrationService;
        private readonly ICustomerService _customerService;
        private readonly IEventService _events;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            ICustomerRegistrationService customerRegistrationService,
            ICustomerService customerService)
        {
            _interaction = interaction;
            _events = events;
            _customerRegistrationService = customerRegistrationService;
            _customerService = customerService;
            _account = new AccountService(interaction, httpContextAccessor, schemeProvider, clientStore);
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await _account.BuildLoginViewModelAsync(returnUrl);
            return View(ViewNames.AccountLogin, vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            if (button != "login")
            {
                // the user clicked the "cancel" button
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var customer = _customerRegistrationService.ValidateCustomer(model.Username, model.Password);

                // validate username/password against in-memory store
                if (customer == Core.Domain.Customers.CustomerLoginResults.Successful)
                {
                    var user = _customerService.GetCustomerByUsername(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.Email, user.Username));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    await HttpContext.SignInAsync(user.Email, user.Username, props);

                    // make sure the returnUrl is still valid, and if so redirect back to authorize endpoint or a local page
                    if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    return Redirect("~/");
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials"));

                ModelState.AddModelError("", AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await _account.BuildLoginViewModelAsync(model);
            return View(ViewNames.AccountLogin, vm);
        }

        [HttpGet]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var props = new AuthenticationProperties()
            {
                RedirectUri = Url.Action("ExternalLoginCallback"),
                Items =
                {
                    { "returnUrl", returnUrl }
                }
            };

            // start challenge and roundtrip the return URL
            props.Items.Add("scheme", provider);
            return Challenge(props, provider);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await _account.BuildLoggedOutViewModelAsync(model.LogoutId);

            var user = HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(user.Identity.Name, user.Identity.Name));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return Redirect(model.ReturnUrl);
        }
    }
}
