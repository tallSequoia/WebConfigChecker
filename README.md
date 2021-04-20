# WebConfigChecker

## Introduction
Identify security configurations issues in ASP.NET web.config files.

## Command line

There is a command line "runner" that just applies a XSLT to a file, called WCCheck.exe. It's primarily a proof of concept and not intended for Production system use.

Just call WCCheck.exe with the path to the web.config. If you have a different location for the web_config.xsl file, that can be specified as the second parameter.

e.g. WCCheck.exe "..\mysite\web.config"
e.g. WCCheck.exe "..\mysite\web.config" "c:\users\tallSequoia\Desktop\myOwn.xslt"

## Sample Results
    <?xml version="1.0" encoding="utf-16"?>
    <findings>
      <finding>connectionStrings/add/@name=AppEntities contains a password in a readable form.</finding>
      <finding>connectionStrings/add/@name=sample.App.My.MySettings.CVVDB contains a password in a readable form.</finding>
      <finding>system.serviceModel/serviceBehaviors/behavior provides metadata on a http endpoint.</finding>
      <finding>system.serviceModel/serviceBehaviors/behavior provides metadata on a https endpoint.</finding>
      <finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit is not defined and has insecure default values.</finding>
      <finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit does not log message authentication failures.</finding>
      <finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit does not log service authorization failures.</finding>
      <finding>system.web/compilation/@debug is set to true.</finding>
      <finding>system.web/compilation/@strict is set to false.</finding>
      <finding>system.web/compilation/@targetFramework is set to an earlier version of the .NET Framework, which is not now in support.</finding>
      <finding>system.web/httpCookies is not defined.</finding>
      <finding>system.web/httpRuntime/@enableVersionHeader is not set to prevent the X-AspNet-Version header being generated.<recommendation>Set the @enableVersionHeader to false</recommendation></finding>
      <finding>system.web/httpRuntime/@targetFramework is set to an earlier version of the .NET Framework, which is not now in support.</finding>
      <finding>system.web/machineKey is not defined, so viewstate protections are not being mandated.<recommendation>Validate the machine.config / applicationhost.config contains these settings</recommendation></finding>
      <finding>system.web/sessionState is not defined.</finding>
      <finding>system.webServer/directoryBrowse/@enabled is enabled.<recommendation>Set to false</recommendation></finding>
      <finding>system.web/httpErrors is not defined.<recommendation>Provide custom error pages from the application.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders is not defined.<recommendation>Use the customHeaders section to set appropriate headers.</recommendation></finding>
      <finding>system.webServer/security/requestFiltering is not defined.<recommendation>Set requestFiltering to manage headers and supported verbs.</recommendation></finding>
    </findings>

and

    <?xml version="1.0" encoding="utf-16"?>
    <findings>
      <finding>configSections/section includes the deprecated UrlRewriter from Intelligencia which is very old and unsupported.<references>See NuGET and validate the project site at http://urlrewriter.net/ is no longer in use.</references></finding>
      <finding>connectionStrings/add/@name=CSP contains a password in a readable form.</finding>
      <finding>connectionStrings/add/@name=CSPConfiguration contains a password in a readable form.</finding>
      <finding>connectionStrings/add/@name=XmitAgent contains a password in a readable form.</finding>
      <finding>connectionStrings/add/@name=CSP_ALT contains a password in a readable form.</finding>
      <finding>connectionStrings/add/@name=CSPConfiguration_REPORTS contains a password in a readable form.</finding>
      <finding>system.codedom/compilers should not be required as all code should be pre-compiled.</finding>
      <finding>system.web/compilation/@debug is set to true.</finding>
      <finding>system.web/compilation/@strict is set to false.</finding>
      <finding>system.web/compilation/@targetFramework is set to an earlier version of the .NET Framework, which is not now in support.</finding>
      <finding class="warning">system.web/httpCookies/@samesite is not set.<recommendation>Set to 'Strict', unless there is a need to support cross site access to cookies.</recommendation></finding>
      <finding>system.web/httpRuntime/@enableVersionHeader is not set to prevent the X-AspNet-Version header being generated.<recommendation>Set the @enableVersionHeader to false</recommendation></finding>
      <finding>system.web/httpRuntime/@targetFramework is set to an earlier version of the .NET Framework, which is not now in support.</finding>
      <finding>system.web/machineKey is not defined, so viewstate protections are not being mandated.<recommendation>Validate the machine.config / applicationhost.config contains these settings</recommendation></finding>
      <finding class="information">system.web/sessionState/@cookieName is not changed from the vendor default.<recommendation>Set to obscure the use of .NET, and prefix with __Host-. See https://www.owasp.org/index.php/Session_Management_Cheat_Sheet</recommendation></finding>
      <finding>system.web/sessionState/@timeout is over 15 minutes.</finding>
      <finding>system.webServer/handlers defines wildcard verbs.<recommendation>Explicitly list all verbs to be used for each hander, e.g. 'GET,HEAD,POST'.</recommendation></finding>
      <finding>system.web/httpErrors/add does not define an error status for error 403.<recommendation>Define an error page for error 403 - Permission Denied.</recommendation></finding>
      <finding class="warning">system.webServer/httpProtocol/customHeaders doesn't remove the X-Powered-By header.<recommendation>Explicitly (try to) remove X-Powered-By, though some versions of IIS do not support this.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't remove the X-AspNet-Version header.<recommendation>Explicitly remove X-AspNet-Version.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the Content-Security-Policy header.<recommendation>Set a Content-Security-Policy.</recommendation></finding>
      <finding class="warning">system.webServer/httpProtocol/customHeaders doesn't set the X-Content-Security-Policy header.<recommendation>Set a X-Content-Security-Policy if legacy browser support is required.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the Expect-CT header.<recommendation>Set a Expect-CT.</recommendation></finding>
      <finding class="warning">system.webServer/httpProtocol/customHeaders doesn't set the Feature-Policy header.<recommendation>Set a Feature-Policy, or use the Permissions-Policy.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the Permissions-Policy header.<recommendation>Set a Permissions-Policy.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the Referrer-Policy header.<recommendation>Set a Referrer-Policy.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the X-Content-Type-Options header.<recommendation>Set a X-Content-Type-Options.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the X-Frame-Options header.<recommendation>Set a X-Frame-Options.</recommendation></finding>
      <finding>system.webServer/httpProtocol/customHeaders doesn't set the X-XSS-Protection header.<recommendation>Set a X-XSS-Protection.</recommendation></finding>
      <finding class="information">system.webServer/httpProtocol/customHeaders doesn't set a Cross-Origin Embedder Policy. This allows a resource to prevent assets being loaded that do not grant permission to load them via CORS or CORP.</finding>
      <finding class="information">system.webServer/httpProtocol/customHeaders doesn't set a Cross-Origin Opener Policy. This allows a resource to opt-in to Cross-Origin Isolation in the user agent.</finding>
      <finding class="information">system.webServer/httpProtocol/customHeaders doesn't set a Cross-Origin Resource Policy. This allows a resource to specify who can load the resource.</finding>
      <finding>system.webServer/modules includes the deprecated UrlRewriter from Intelligencia which is very old and unsupported.<references>See NuGET and validate the project site at http://urlrewriter.net/ is no longer in use.</references></finding>
      <finding>system.webServer/security/requestFiltering is not defined.<recommendation>Set requestFiltering to manage headers and supported verbs.</recommendation></finding>
      <finding>system.webServer/validation/@validateIntegratedModeConfiguration is disabled.<recommendation>Migrate settings to the IIS7+ method and then enable this or remove the element.</recommendation></finding>
    </findings>
    
