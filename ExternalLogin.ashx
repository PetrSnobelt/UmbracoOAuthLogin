<%@ WebHandler Language="C#" Class="ExternalLogin" %>

using System;
using System.Web;
using System.Linq;
//Used to add user
using umbraco.BusinessLogic;

using System.Web.Security;
using Umbraco.Core;
using Umbraco.Core.Configuration;
using Umbraco.Core.Models.Membership;
using Umbraco.Web;
using Umbraco.Core.Security;
using Umbraco.Web.Security;
using Umbraco.Web.WebApi;
using Umbraco.Web.WebApi.Filters;
using umbraco.providers;

using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;

//https://github.com/owin-middleware/OwinOAuthProviders
//Umbraco\Views\common\dialogs\login.html

public class ExternalLogin : IHttpHandler {

    const string CallBackKey = "Callback";
    
    public void ProcessRequest(HttpContext context)
    {
        //string email = "petr.snobelt@gmail.com";
        //LogInByEmail(context, email, "debug");
               
        IAuthenticationManager authManager = context.GetOwinContext().Authentication;
        if (string.IsNullOrEmpty(context.Request.QueryString[CallBackKey]))
        {
            string providerName = context.Request.QueryString["provider"] ?? "Google";
            RedirectToProvider(context, authManager, providerName);            
        }
        else
        {
            ExternalLoginCallback(context, authManager);
        }        
    }

    private static void RedirectToProvider(HttpContext context, IAuthenticationManager authManager, string providerName)
    {
        var loginProviders = authManager.GetExternalAuthenticationTypes();

        var LoginProvider = loginProviders.Single(x => x.Caption == providerName);

        var properties = new AuthenticationProperties()
        {
            RedirectUri = String.Format("{0}?{1}=true", context.Request.Url, CallBackKey)
        };
        
        //string[] authTypes = { LoginProvider.AuthenticationType, DefaultAuthenticationTypes.ExternalCookie };
        authManager.Challenge(properties, LoginProvider.AuthenticationType);

        //without this it redirect to forms login page
        context.Response.SuppressFormsAuthenticationRedirect = true;
    }

    public void ExternalLoginCallback(HttpContext context, IAuthenticationManager authManager)
    {
        var loginInfo = authManager.GetExternalLoginInfo();
        if (loginInfo == null)
        {
            throw new System.Security.SecurityException("Failed to login");
        }

        var LoginProvider = loginInfo.Login.LoginProvider;
        var ExternalLoginConfirmation = loginInfo.DefaultUserName;

        var externalIdentity = authManager.GetExternalIdentityAsync(DefaultAuthenticationTypes.ExternalCookie);
        var emailClaim = externalIdentity.Result.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
        var email = emailClaim.Value;
        LogInByEmail(context, email, LoginProvider);
    }

    private static void LogInByEmail(HttpContext context, string email, string loginProvider)
    {
        User[] users = umbraco.BusinessLogic.User.getAllByEmail(email, useExactMatch: true);
        if (users.Length != 1) throw new System.Security.SecurityException("Cannot find user with email " + email);

        var user = users[0];
        
        //it looks like it don't work
        Log.Add(LogTypes.Login, user, -1, "Logged in using external provider " + loginProvider);
        
        var umbracoContext = Umbraco.Web.UmbracoContext.Current;
        var ticket = umbracoContext.Security.PerformLogin(user.Id);

        context.Response.Redirect("/umbraco/");
    }
    
    public bool IsReusable
    {
        get {
            return false;
        }
    }
}