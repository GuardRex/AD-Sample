using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Authentication.Cookies;
using System.Threading.Tasks;

namespace AzureADTest50.Controllers {

    [RequireHttps]
    public class AccountController : Controller {

        [HttpGet]
        [AllowAnonymous]
        [Route("/account/login")]
        public IActionResult LogIn(string returnUrl = null)
        {
            if (Context.User == null || !Context.User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(OpenIdConnectAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("/account/logout")]
        public async Task LogOut()
        {
            await Context.Authentication.SignOutAsync(OpenIdConnectAuthenticationDefaults.AuthenticationScheme);
            await Context.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

    }
}