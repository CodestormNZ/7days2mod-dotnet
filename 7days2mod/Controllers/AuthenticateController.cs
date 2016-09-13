using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace _7days2mod.Controllers
{
    public class AuthenticateController : Controller
    {
        // GET: Authenticate
        public ActionResult Index(string return_url)
        {
            string baseUrl = Request.Url.GetLeftPart(UriPartial.Authority);
            if (return_url == null)
            {
                return_url = Convert.ToBase64String(Encoding.UTF8.GetBytes(baseUrl));
            }
            var keygen = new App_Code.KeyGenerator();
            Session["CSRF:State"] = keygen.GetUniqueKey(64);
            var requestURL = "https://github.com/login/oauth/authorize"
                + "?client_id=" + ConfigurationManager.AppSettings["GitHubOAuthClientID"]
                + "&redirect_uri=" + baseUrl + "/Authenticate/Verify/" + return_url
                + "&state=" + Session["CSRF:State"]
                + "&scope=user%20public_repo";
            return Redirect(requestURL);
        }

        // GET: Authenticate/Verify
        public async Task<ActionResult> Verify(string id, string code, string state)
        {
            if (String.IsNullOrEmpty(code))
            {
                return RedirectToAction("Index");
            }
            string return_url = "";
            if (id != null)
            {
                return_url = Encoding.UTF8.GetString(Convert.FromBase64String(id));
            }
            if ((string)Session["CSRF:State"] == state)
            {
                // state matches session value, proceed with token aquisition
                using (var client = new HttpClient())
                {
                    client.BaseAddress = new Uri("https://github.com/");
                    client.DefaultRequestHeaders.Accept.Clear();
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    //set post variables
                    var values = new Dictionary<string, string>
                    {
                        { "client_id", ConfigurationManager.AppSettings["GitHubOAuthClientID"] },
                        { "client_secret", ConfigurationManager.AppSettings["GitHubOAuthClientSecret"] },
                        { "code", code },
                        { "state", state },
                    };
                    var content = new FormUrlEncodedContent(values);

                    HttpResponseMessage response = await client.PostAsync("login/oauth/access_token", content);
                    if (response.IsSuccessStatusCode)
                    {
                        var responseString = await response.Content.ReadAsStringAsync();
                        dynamic responseData = JObject.Parse(responseString);
                        if (responseData.error == "bad_verification_code")
                        {
                            return Redirect(Request.Url.GetLeftPart(UriPartial.Authority) + "/Authenticate");
                        }
                        else
                        {
                            Session["access_token"] = responseData.access_token;
                            Session["scope"] = responseData.scope;
                            using (var client2 = new HttpClient())
                            {

                                client2.BaseAddress = new Uri("https://api.github.com/");
                                client2.DefaultRequestHeaders.Accept.Clear();
                                client2.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                                client2.DefaultRequestHeaders.UserAgent.ParseAdd("7days2mod-app");
                                HttpResponseMessage userResponse = await client2.GetAsync("user?access_token=" + responseData.access_token);
                                if (userResponse.IsSuccessStatusCode)
                                {
                                    var userResponseString = await userResponse.Content.ReadAsStringAsync();
                                    dynamic userResponseData = JObject.Parse(userResponseString);
                                    Session["user_login"] = (string)userResponseData.login;
                                    Session["user_avatar"] = (string)userResponseData.avatar_url;
                                }
                            }
                            return Redirect(return_url);
                        }
                    }
                }
            }
            //state match failed, return exception
            return View("Error");
        }
    }
}
