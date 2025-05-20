using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;
using Google.Authenticator;
using googleAuthenticator.Models;
using googleAuthenticator.CaseServiceRef;
using googleAuthenticator.Models;



namespace googleAuthenticator.Controllers
{
    public class HomeController : Controller
    {
        // This method shows the main page only if the user is logged in and passed two-factor authentication
        public ActionResult Index()
        {
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                return RedirectToAction("Login");
            }
            return View();
        }

        // This method shows the About page only if the user is logged in and passed two-factor authentication
        public ActionResult About()
        {
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                return RedirectToAction("Login");
            }

            ViewBag.Message = "Your application description page.";
            return View();
        }

        // This method shows the Contact page only if the user is logged in and passed two-factor authentication
        public ActionResult Contact()
        {
            if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                return RedirectToAction("Login");
            }
            ViewBag.Message = "Your contact page.";
            return View();
        }

        // This method clears any existing login session and shows the login page
        public ActionResult Login()
        {
            Session["UserName"] = null;
            Session["IsValidTwoFactorAuthentication"] = null;
            return View();
        }

        // This method handles the login form submission
        // It checks the username and password,
        // and sets up Google two-factor authentication
        [HttpPost]
        public ActionResult Login(LoginModel login)
        {
            bool status = false;
            if (Session["Username"] == null || 
                Session["IsValidTwoFactorAuthentication"] == null || 
                !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                string googleAuthKey = WebConfigurationManager.AppSettings["GoogleAuthKey"];
                string UserUniqueKey = (login.UserName + googleAuthKey);

                // Hardcoded login check - only works for "Admin" with password "12345"
                if (login.UserName == "Admin" && login.Password == "12345")
                {
                    Session["UserName"] = login.UserName;

                    // Create Google Authenticator setup with QR code and manual entry key
               
                    TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
                   var setupInfo = TwoFacAuth.GenerateSetupCode("Googleauthenticator.com", login.UserName, ConvertSecretToBytes(UserUniqueKey, false), 300);

                    Session["UserUniqueKey"] = UserUniqueKey;
                  ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                    ViewBag.SetupCode = setupInfo.ManualEntryKey;
                    status = true;
                }
            }
            else
            {

                return RedirectToAction("CaseForm");
            }

            ViewBag.Status = status;
            return View();
        }

        // This helper method converts the user secret into bytes (for 2FA setup)
        private static byte[] ConvertSecretToBytes(string secret, bool secretIsBase32)
           => secretIsBase32 ? Base32Encoding.ToBytes(secret) : Encoding.UTF8.GetBytes(secret);

        // This method verifies the 2FA code entered by the user
        public ActionResult TwoFactorAuthenticate()
        {
            var token = Request["CodeDigit"];
          TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
            string UserUniqueKey = Session["UserUniqueKey"].ToString();

            // Validates the entered PIN using Google Authenticator
          bool isValid = TwoFacAuth.ValidateTwoFactorPIN(UserUniqueKey, token, false);
           if (isValid)
            {
                HttpCookie TwoFCookie = new HttpCookie("TwoFCookie");
                string UserCode = Convert.ToBase64String(MachineKey.Protect(Encoding.UTF8.GetBytes(UserUniqueKey)));
                Session["IsValidTwoFactorAuthentication"] = true;

                return RedirectToAction("CaseForm");
            }

            ViewBag.Message = "Google Two Factor PIN is expired or wrong";
            return RedirectToAction("Login");
        }

        // This method logs the user out by clearing session values and redirects to login
        public ActionResult Logoff()
        {
            Session["UserName"] = null;
            Session["IsValidTwoFactorAuthentication"] = null;
            return RedirectToAction("Login");
        }

        // GET: Show the form after 2FA
        public ActionResult CaseForm()
        {
            if (Session["UserName"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        // POST: Submit case data and get sensitive field results
        [HttpPost]
        public ActionResult CaseForm(CaseInputModel model)
        {
            if (Session["UserName"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            {
                return RedirectToAction("Login");
            }

            var service = new CriminalCaseService();
            var resultList = service.CheckSensitiveData(
                model.CaseNumber,
                model.InformantID,
                model.PoliceBadgeID,
                model.ProtectedAddress
            );

            ViewBag.Result = resultList;
            return View(model);
        }



    }
}
