using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Security.Claims;
using System.Net.Http;
using System.Linq;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using Microsoft.AspNet.Builder;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Configuration;
using System;
using Microsoft.AspNet.Hosting;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNet.Authentication.OpenIdConnect;

namespace ADSample
{
    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public static string ClientId = string.Empty;
        public static string Tenant = string.Empty;
        public static string AppKey = string.Empty;
        public static string PostLogoutRedirectUri = string.Empty;
        public static string GraphApiVersion = string.Empty;

        public Startup(IHostingEnvironment env)
        {
            var configurationBuilder = new ConfigurationBuilder().AddEnvironmentVariables();
            Configuration = configurationBuilder.Build();
            string machineName = Environment.GetEnvironmentVariable("COMPUTERNAME");
            if(machineName.StartsWith("XXXXXX", StringComparison.OrdinalIgnoreCase))
            {
                Configuration["ASPNET_ENV"] = "Production";
            }
            else if (machineName.StartsWith("XXXXXX", StringComparison.OrdinalIgnoreCase))
            {
                Configuration["ASPNET_ENV"] = "Production";
            }
            else
            {
                Configuration["ASPNET_ENV"] = "Development";
            }
            Configuration["MachineName"] = machineName;
            Configuration["DevelopmentIp"] = "111.222.333.444";
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAntiforgery();
            services.AddSingleton(_ => Configuration);
            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseErrorPage();
            }
            else
            {
                app.UseErrorHandler("/error");
            }
            app.UseStaticFiles();
            app.Use((context, next) =>
            {
                context.Response.Headers.Remove("Server");
                context.Response.Headers.Append("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
                return next();
            });
            Tenant = "XXXXXX.onmicrosoft.com";
            ClientId = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
            AppKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=";
            PostLogoutRedirectUri = "https://www.XXXXXX.com/";
            GraphApiVersion = "1.6";

            // Middleware for OpenId Connect & Graph API
            app.UseCookieAuthentication(options => {
                options.AutomaticAuthentication = true;
            });
            app.UseOpenIdConnectAuthentication(options => {
                options.ClientId = ClientId;
                options.Authority = $"https://login.microsoftonline.com/{Tenant}";
                options.PostLogoutRedirectUri = PostLogoutRedirectUri;
                options.AutomaticAuthentication = true;
                options.Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = (context) => {
                        return Task.FromResult(0);
                    },
                    AuthenticationFailed = (context) => {
                        context.HandleResponse();
                        context.Response.Redirect("/error/401");
                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async (context) => {
                        string responseContent1 = "";
                        string responseContent2 = "";
                        if (context.AuthenticationTicket.Principal.Identity.IsAuthenticated)
                        {
                            AuthenticationResult authResult;
                            ClientCredential credential = new ClientCredential(ClientId, AppKey);
                            AuthenticationContext authContext = new AuthenticationContext(options.Authority);
                            try
                            {
                                authResult = await authContext.AcquireTokenAsync("https://graph.windows.net", credential);
                                if (authResult != null)
                                {
                                    string userObjectId = context.AuthenticationTicket.Principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
                                    using (var httpClient = new HttpClient())
                                    {
                                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);
                                        var graphRequestResult = await httpClient.GetAsync($"https://graph.windows.net/{Tenant}/users/{Uri.EscapeUriString(userObjectId)}/memberOf?api-version={GraphApiVersion}");
                                        if (graphRequestResult.IsSuccessStatusCode)
                                        {
                                            responseContent2 = await graphRequestResult.Content.ReadAsStringAsync();
                                            if (responseContent2 != null)
                                            {
                                                JObject jsonResponse = JObject.Parse(responseContent2);
                                                var roles = jsonResponse["value"].Children().Select(e => new { DisplayName = e.Value<string>("displayName") });
                                                foreach (var role in roles)
                                                {
                                                    ((ClaimsIdentity)context.AuthenticationTicket.Principal.Identity).AddClaim(new Claim(ClaimTypes.Role, role.DisplayName, ClaimsIdentity.DefaultRoleClaimType));
                                                }
                                            }
                                        }
                                        else
                                        {                                        
                                            StringBuilder sb = new StringBuilder();
                                            foreach (var h in graphRequestResult.RequestMessage.Headers)
                                            {
                                                foreach (var hv in h.Value)
                                                {
                                                    sb.Append(h.Key + "=" + hv + " ");
                                                }
                                            }
                                            responseContent2 = "2 Status Code: " + graphRequestResult.StatusCode.ToString() + " Reason: " + graphRequestResult.ReasonPhrase + " Headers: " + sb.ToString();
                                        }
                                    }
                                }
                                else
                                {
                                    responseContent2 = "Failed to acquire token for Graph API.";
                                }
                            }
                            catch (Exception ex)
                            {
                                responseContent2 = ex.ToString();
                            }
                        }
                        else
                        {
                            responseContent2 = "You were not authenticated by Azure Active Directory.";
                        }

                        if (responseContent1.Length > 0 && !responseContent1.StartsWith("{"))
                        {
                            var extraClaims = new Claim[] {
                                new Claim(ClaimTypes.UserData, responseContent1)
                            };
                            context.AuthenticationTicket.Principal.AddIdentity(new ClaimsIdentity(extraClaims, OpenIdConnectAuthenticationDefaults.AuthenticationScheme));
                        }
                        if (responseContent2.Length > 0 && !responseContent2.StartsWith("{"))
                        {
                            var extraClaims = new Claim[] {
                                new Claim(ClaimTypes.UserData, responseContent2),
                            };
                            context.AuthenticationTicket.Principal.AddIdentity(new ClaimsIdentity(extraClaims, OpenIdConnectAuthenticationDefaults.AuthenticationScheme));
                        }
                    }
                };
            });
            app.UseMvcWithDefaultRoute();
        }
    }
}
