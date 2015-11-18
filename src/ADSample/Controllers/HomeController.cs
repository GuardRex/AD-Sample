using Microsoft.AspNet.Mvc;
using System;
using Microsoft.AspNet.Authorization;

namespace ADSample
{
    [RequireHttps]
    public class HomeController : Controller
    {
        [Route("/error/{v?}")]
        public IActionResult Error(string v)
        {
            switch (v)
            {
                case "404":
                    ViewBag.Exception = "404 - Not Found";
                    Context.Response.StatusCode = 404;
                    break;
                case "403":
                    ViewBag.Exception = "403 - Forbidden";
                    Context.Response.StatusCode = 403;
                    break;
                case "401":
                    ViewBag.Exception = "401 - Unauthorized";
                    // Return a 200 OK b/c a 401 will result in an infinite loop
                    // with the RedirectToIdentityProvider notification in Startup
                    Context.Response.StatusCode = 200;
                    break;
                default:
                    ViewBag.Exception = "400 - Bad Request";
                    Context.Response.StatusCode = 400;
                    break;
            }
            return View("error");
        }

        [HttpGet]
        [Route("/")]
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult UserAuthorized()
        {
            return View();
        }

        [Authorize(Roles = "Company Administrator,Global Administrators,Billing Administrators,Identity Administrators,Service Administrators,User Administrators,Password Administrators")]
        public IActionResult AdministratorAuthorized()
        {
            return View();
        }
    }
}

