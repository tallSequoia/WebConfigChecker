<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="xml" version="1.0" encoding="UTF-8" indent="yes"/>


<xsl:template match="/configuration">

<findings>
  <xsl:apply-templates select="appSettings" />
  <xsl:apply-templates select="connectionStrings" />
  <xsl:apply-templates select="system.codedom" />
  <xsl:apply-templates select="system.serviceModel" />
  <xsl:apply-templates select="system.web" />
  <xsl:apply-templates select="system.webServer"/>
</findings>

</xsl:template>


<xsl:template match="appSettings">

  <xsl:for-each select="add">
    <xsl:call-template name="keyValuePassword">
      <xsl:with-param name="area">appSettings/add/@key=</xsl:with-param>
      <xsl:with-param name="key"><xsl:value-of select="./@key" /></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="./@value" /></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>

</xsl:template>


<xsl:template match="connectionStrings">
  <xsl:for-each select="add">
    <xsl:call-template name="keyValuePassword">
      <xsl:with-param name="area">connectionStrings/add/@name=</xsl:with-param>
      <xsl:with-param name="key"><xsl:value-of select="./@name" /></xsl:with-param>
      <xsl:with-param name="value"><xsl:value-of select="./@connectionString" /></xsl:with-param>
    </xsl:call-template>
  </xsl:for-each>
</xsl:template>


<xsl:template match="system.codedom">
  <!-- Production systems shouldn't need any compilers as it may cause uploaded files to be compiled and run -->
  <xsl:if test="compilers"><finding>system.codedom/compilers should not be required as all code should be pre-compiled.</finding></xsl:if>
  <xsl:if test="compilers[count(./compiler) &gt; 1]"><finding>system.codedom/compilers defines multiple source languages.</finding></xsl:if>
</xsl:template>


<xsl:template match="system.serviceModel">
  <xsl:if test="behaviors/serviceBehaviors/behavior">
    <xsl:if test="behaviors/serviceBehaviors/behavior/serviceMetadata[@httpGetEnabled='true']"><finding>system.serviceModel/serviceBehaviors/behavior provides metadata on a http endpoint.</finding></xsl:if>  
    <xsl:if test="behaviors/serviceBehaviors/behavior/serviceMetadata[@httpsGetEnabled='true']"><finding>system.serviceModel/serviceBehaviors/behavior provides metadata on a https endpoint.</finding></xsl:if>  

    <xsl:if test="behaviors/serviceBehaviors/behavior/serviceDebug[@includeExceptionDetailInFaults='true']"><finding>system.serviceModel/serviceBehaviors/behaviour/serviceDebug may include exception detail in faults to users.</finding></xsl:if>

    <!-- source: https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/servicesecurityaudit -->
    <xsl:if test="not(behaviors/serviceBehaviors/behavior/serviceSecurityAudit)"><finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit is not defined and has insecure default values.</finding></xsl:if>
    <xsl:if test="not(behaviors/serviceBehaviors/behavior/serviceSecurityAudit[@messageAuthenticationAuditLevel='SuccessOrFailure']) and not(behaviors/serviceBehaviors/behavior/serviceSecurityAudit[@messageAuthenticationAuditLevel='Failure'])"><finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit does not log message authentication failures.</finding></xsl:if>
    <xsl:if test="not(behaviors/serviceBehaviors/behavior/serviceSecurityAudit[@serviceAuthorizationAuditLevel='SuccessOrFailure']) and not(behaviors/serviceBehaviors/behavior/serviceSecurityAudit[@serviceAuthorizationAuditLevel='Failure'])"><finding>system.serviceModel/serviceBehaviors/behaviour/serviceSecurityAudit does not log service authorization failures.</finding></xsl:if>
  </xsl:if>

  <xsl:if test="protocolMapping/add[@scheme='http']"><finding>system.serviceModel/protocolMapping provides a http endpoint.<recommendation>Support only https endpoints</recommendation></finding></xsl:if>
</xsl:template>


<xsl:template match="system.web">

  <!-- anonymousIdentification -->
  <xsl:if test="anonymousIdentification[@enabled='true']">

    <xsl:if test="anonymousIdentification/@cookieless and not(anonymousIdentification[@cookieless='UseCookies'])"><finding>system.web/anonymousIdentification/@cookieless is set to (potentially) expose the session identifier.<recommendation>Set to 'UseCookies'.</recommendation></finding></xsl:if>

    <xsl:if test="not(anonymousIdentification/@cookieName) or (anonymousIdentification[@cookieName='.ASPXANONYMOUS'])"><finding class="information">system.web/anonymousIdentification/@cookieName is unchanged from the vendor default.<recommendation>Set to begin __Host- and not related to authentication.</recommendation></finding></xsl:if>

    <xsl:if test="not(anonymousIdentification/@cookiePath)"><finding class="information">system.web/anonymousIdentification/@cookiePath is unchanged.<recommendation>Consider setting to the smallest scope required.</recommendation></finding></xsl:if>

    <!-- source: https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.anonymousidentificationsection.cookieprotection -->
    <xsl:if test="anonymousIdentification[@cookieProtection='None']"><finding>system.web/anonymousIdentification/@cookieProtection is disabled.<recommendation>Set to all as per manufacturer recommendation.</recommendation></finding></xsl:if>

    <xsl:if test="not(anonymousIdentification/@cookieRequireSSL) or anonymousIdentification[@cookieRequireSSL!='true']"><finding>system.web/anonymousIdentification/@cookieRequireSSL is not set.<recommendation>Ensure that SSL is required for the cookie.</recommendation></finding></xsl:if>
  </xsl:if>


  <!-- authentication -->
  <!-- source: https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff649308(v=pandp.10) -->

  <xsl:if test="authentication[@mode='Forms'] and authentication/forms">
    <xsl:if test="not(authentication/forms/@name) or authentication/forms[@name='.ASPXAUTH']"><finding class="information">system.web/authentication/forms/@name is unchanged from the vendor default.<recommendation>Set to begin __Host- and not related to authentication</recommendation></finding></xsl:if>
    
    <xsl:if test="authentication/forms/@protection and not(authentication/forms[@protection='All'])"><finding>system.web/authentication/forms/@protection is insecure.<recommendation>Set to All</recommendation></finding></xsl:if>

    <xsl:if test="not(authentication/forms/@requireSSL) or authentication/forms[@requireSSL='false']"><finding>system.web/authentication/forms/@requireSSL is set insecurely.<recommendation>Set to true</recommendation></finding></xsl:if>

    <xsl:if test="authentication/forms[@timeout &lt; 5]"><finding>system.web/authentication/forms/@timeout is short.<recommendation>Set to 15</recommendation></finding></xsl:if>
    <xsl:if test="authentication/forms[@timeout &gt; 15] or not(authentication/forms/@timeout)"><finding>system.web/authentication/forms/@timeout is very long.<recommendation>Set to 15</recommendation></finding></xsl:if>

    <!-- source: https://docs.microsoft.com/en-us/dotnet/api/system.web.security.formsauthentication.enablecrossappredirects?view=netframework-4.8 -->
    <xsl:if test="authentication/forms[@enableCrossAppRedirects='true']"><finding>system.web/authentication/forms/@enableCrossAppRedirects is enabled.<recommendation>Disable unless needed and recommended protection is implemented</recommendation></finding></xsl:if>
    
    <xsl:choose>
      <xsl:when test="authentication/forms/credentials[@passwordFormat='Clear']">
        <finding>system.web/authentication/forms/credentials/@passwordFormat is set to not protect the passwords.<recommendation>Set to SHA256</recommendation></finding>

        <xsl:for-each select="authentication/forms/credentials/user">
          <xsl:call-template name="keyValuePassword">
            <xsl:with-param name="area">system.web/authentication/forms/credentials/user=<xsl:value-of select="./@name" /> </xsl:with-param>
            <xsl:with-param name="key">password</xsl:with-param>    <!-- tell the template that this is a password to allow reuse -->
            <xsl:with-param name="value"><xsl:value-of select="./@password" /></xsl:with-param>
          </xsl:call-template>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:if test="authentication/forms/credentials[@passwordFormat] and not(authentication/forms/credentials[@passwordFormat='SHA256'])"><finding>system.web/authentication/forms/credentials/@passwordFormat is set to a weak hashing algorithm.<recommendation>Set to SHA256</recommendation></finding></xsl:if>          
      </xsl:otherwise>
    </xsl:choose>
  </xsl:if>


  <!-- compilation -->

  <xsl:if test="not(compilation)"><finding>system.web/compilation is not defined.</finding></xsl:if>
  <xsl:if test="compilation[@debug='true']"><finding>system.web/compilation/@debug is set to true.</finding></xsl:if>
  <xsl:if test="compilation[@explicit='false']"><finding>system.web/compilation/@explicit is set to false.</finding></xsl:if>
  <xsl:if test="compilation[@strict='false']"><finding>system.web/compilation/@strict is set to false.</finding></xsl:if>
  <xsl:if test="compilation[@targetFramework &lt; 4.7]"><finding class="warning">system.web/compilation/@targetFramework may be set to an earlier version of the .NET Framework.</finding></xsl:if>


  <!-- This is legacy. source: https://tedgustaf.com/blog/2011/custom-404-and-error-pages-for-asp-net-and-static-files/ (and https://stackoverflow.com/questions/2480006/what-is-the-difference-between-customerrors-and-httperrors#18404091) -->
<!-- 
TODO: Have no opinion for now, but need to review in a bit more depth

  <xsl:if test="not(customErrors)"><finding>system.web/customErrors is not defined.</finding></xsl:if>
  <xsl:if test="customErrors[@mode='Off']"><finding>system.web/customErrors/@mode is set off.</finding></xsl:if>

TODO: Validate a custom generic or secific entries?
-->
  <xsl:if test="httpErrors"><finding>system.web/httpErrors is not processed - this is a system.webServer setting.</finding></xsl:if>


  <!-- deployment -->
  <xsl:if test="deployment[@retail='true']"><finding>system.web/deployment/retail is set, and cause issues in web.config files.<recommendation>Move to the machine.config</recommendation></finding></xsl:if>


  <!-- httpCookies -->

  <xsl:if test="not(httpCookies)"><finding>system.web/httpCookies is not defined.</finding></xsl:if>
  <xsl:if test="httpCookies">
    <xsl:if test="not(httpCookies/@httpOnlyCookies) or httpCookies[@httpOnlyCookies='false']"><finding class="warning">system.web/httpCookies/@httpOnlyCookies should be set to 'true', unless there is a need for javascript access.</finding></xsl:if>
    <xsl:if test="not(httpCookies/@requireSSL) or httpCookies[@requireSSL='false']"><finding>system.web/httpCookies/@requireSSL is not set.<recommendation>Set on unless HTTPS is not in use.</recommendation></finding></xsl:if> <!-- GDPR and DSS and anti-XSS-->
    <xsl:if test="not(httpCookies/@samesite) or httpCookies[@samesite='Lax']"><finding class="warning">system.web/httpCookies/@samesite is not set.<recommendation>Set to 'Strict', unless there is a need to support cross site access to cookies.</recommendation></finding></xsl:if> <!-- GDPR and anti-XSS -->
  </xsl:if>


  <!-- httpRuntime -->

  <xsl:if test="httpRuntime[@executionTimeout &lt; 15]"><finding>system.web/httpRuntime/@executionTimeout is very short.</finding></xsl:if>
  <xsl:if test="httpRuntime[@executionTimeout &gt; 180]"><finding>system.web/httpRuntime/@executionTimeout is very long.</finding></xsl:if>

  <xsl:if test="not(httpRuntime/@enableVersionHeader) or httpRuntime[@enableVersionHeader='true']"><finding>system.web/httpRuntime/@enableVersionHeader is not set to prevent the X-AspNet-Version header being generated.<recommendation>Set the @enableVersionHeader to false</recommendation></finding></xsl:if>

  <xsl:if test="httpRuntime[@enableHeaderChecking='false']"><finding>system.web/httpRuntime/@enableHeaderChecking has been disabled.</finding></xsl:if>

  <xsl:if test="httpRuntime[@relaxedUrlToFileSystemMapping='true']"><finding>system.web/httpRuntime/@relaxedUrlToFileSystemMapping has been enabled.</finding></xsl:if>

  <xsl:if test="httpRuntime/@requestPathInvalidCharacters and httpRuntime[string-length(@requestPathInvalidCharacters) &lt; 9]"><finding>system.web/httpRuntime/@requestPathInvalidCharacters has been altered to remove dangerous characters.</finding></xsl:if>

  <xsl:if test="httpRuntime[@targetFramework &lt; 4.5]"><finding class="warning">system.web/httpRuntime/@targetFramework may be set to an earlier version of the .NET Framework.</finding></xsl:if>



  <!-- machineKey -->

  <xsl:if test="not(machineKey)"><finding>system.web/machineKey is not defined, so viewstate protections are not being mandated - validate the machine.config / applicationhost.config.</finding></xsl:if>

  <xsl:if test="machineKey[@decryption] and not(machineKey[@decryption='AES']) and not(machineKey[@decryption='Auto'])"><finding class="warning">system.web/machineKey/@decryption does not force AES encryption for the viewstate.<recommendation>If sensitive data are being placed in the viewstate, set the decryption value to AES, Auto, or retain the system default.</recommendation></finding></xsl:if>

  <!-- decryptionKey set to something specific and readable is the publication of the key in to an unencrypted form which MAY protect CHD under DSS -->
  <xsl:if test="machineKey[@decryptionKey] and not(machineKey[contains(@decryptionKey, 'enerate')]) and not(machineKey[contains(@decryptionKey, 'solate')])"><finding>system.web/machineKey/@decryptionKey specifies the encryption key in clear text.</finding></xsl:if>

  <xsl:if test="machineKey and not(machineKey[@validation])"><finding>system.web/machineKey does not force strong validation for the viewstate.</finding></xsl:if>
  <xsl:if test="machineKey[@validation] and not(machineKey[@validation='HMACSHA256'] or machineKey[@validation='HMACSHA384'] or machineKey[@validation='HMACSHA512'])"><finding>system.web/machineKey/@validation specifies a weak validation algorithm (<xsl:value-of select="machineKey/@validation" />) for the viewstate.</finding></xsl:if>

  <!-- validationKey set to something specific and readable is the publication of the key in to an unencrypted form which is not very DSS -->
  <xsl:if test="machineKey[@validationKey] and not(machineKey[contains(@validationKey, 'enerate')]) and not(machineKey[contains(@validationKey, 'solate')])"><finding>system.web/machineKey/@validationKey specifies the validation key in clear text.</finding></xsl:if>

  <xsl:if test="machineKey[@validationKey] and machineKey[@decryptionKey]=machineKey[@validationKey] and not(machineKey[contains(@decryptionKey,'solate')]) and not(machineKey[contains(@decryptionKey,'enerate')])"><finding>system.web/machineKey has the same validation and decryption key.</finding></xsl:if>


  <!-- membership -->

  <xsl:if test="membership and not(membership/@hashAlgorithmType)"><finding>system.web/membership/@hashAlgorithmType provider is undefined so may use insecure hashing algorithm.</finding></xsl:if>
  <xsl:if test="membership[@hashAlgorithmType='SHA1']"><finding>system.web/membership/@hashAlgorithmType provider uses insecure hashing algorithm.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@enablePasswordRetrieval='true']"><finding>system.web/membership/providers/@enablePasswordRetrieval provider allows password retrieval.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@maxInvalidPasswordAttempts &gt; 6]"><finding>system.web/membership/providers/@maxInvalidPasswordAttempts allows large number of password attempts.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@minRequiredPasswordLength &lt; 8]"><finding>system.web/membership/providers/@minRequiredPasswordLength allows short password length.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@minRequiredNonalphanumericCharacters = 0]"><finding>system.web/membership/providers/@minRequiredNonalphanumericCharacters doesn't require symbols.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@passwordFormat != 'Hashed']"><finding>system.web/membership/providers/@passwordFormat doesn't require Hashed storage.</finding></xsl:if>

  <xsl:if test="membership/providers/add[@passwordAttemptWindow &lt; 30]"><finding>system.web/membership/providers/@passwordAttemptWindow allows short password attempt window.</finding></xsl:if>


  <!-- pages -->

  <!-- source: https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff649308(v=pandp.10) -->
  <xsl:if test="pages[@enableViewStateMac='false']"><finding>system.web/pages/@enableViewStateMac is disabled.</finding></xsl:if>

  <xsl:if test="pages[@viewStateEncryptionMode='Never']"><finding>system.web/pages/@viewStateEncryptionMode is disabled.</finding></xsl:if>

  <!-- source: https://docs.microsoft.com/en-us/previous-versions/msp-n-p/ff649308(v=pandp.10) -->
  <xsl:if test="pages[@validateRequest='false']"><finding>system.web/pages/@validateRequest is disabled.</finding></xsl:if>


  <!-- roleManager -->

  <xsl:if test="roleManager[@cookieProtection='None']"><finding>system.web/roleManager/@cookieProtection is disabled.</finding></xsl:if>
  <xsl:if test="roleManager[@cookieRequireSSL='false']"><finding>system.web/roleManager/@cookieRequireSSL should be set as 'true'.</finding></xsl:if>
  <xsl:if test="roleManager[@createPersistentCookie='true']"><finding>system.web/roleManager/@createPersistentCookie should be disabled.</finding></xsl:if>


  <!-- sessionState -->

  <xsl:if test="not(sessionState)"><finding>system.web/sessionState is not defined.</finding></xsl:if>

  <xsl:if test="sessionState/@cookieless and not(sessionState[@cookieless='UseCookies'])"><finding>system.web/sessionState/@cookieless is set to is set to (potentially) expose the session identifier.<recommendation>Set to 'UseCookies'.</recommendation></finding></xsl:if>

  <xsl:if test="sessionState and not(sessionState[@cookieName])"><finding class="information">system.web/sessionState/@cookieName is not changed from the vendor default.<recommendation>Set to obscure the use of .NET, and prefix with __Host-</recommendation></finding></xsl:if>

  <xsl:if test="sessionState[contains(translate(@sqlConnectionString, 'PASWORD', 'pasword'), 'password')]">
    <xsl:call-template name="keyValuePassword">
      <xsl:with-param name="area">system.web/sessionState/@sqlConnectionString </xsl:with-param>
      <xsl:with-param name="key">password</xsl:with-param>    <!-- tell the template that this is a password to allow reuse -->
      <xsl:with-param name="value"><xsl:value-of select="./@sqlConnectionString" /></xsl:with-param>
    </xsl:call-template>
  </xsl:if>

  <xsl:if test="sessionState and not(sessionState[@timeout])"><finding>system.web/sessionState/@timeout is not defined, and the default is 20 minutes.</finding></xsl:if>
  <xsl:if test="sessionState[@timeout &gt; 15]"><finding>system.web/sessionState/@timeout is over 15 minutes.</finding></xsl:if>


  <!-- trace -->
  <xsl:if test="trace[@enabled='true']"><finding>system.web/trace/@enabled is enabled.<recommendation>Set to false to disable tracing.</recommendation></finding></xsl:if>


  <!-- webServices -->
  <xsl:if test="(webServices/protocols/clear and webServices/protocols/add[@name='Documentation']) or (webServices/protocols and not(webServices/protocols/remove[@name='Documentation']))"><finding>system.web/webServices/protocols enables WSDL documentation.<recommendation>Remove the Documentation by using the Remove element or by clearing all entries and defining what is needed</recommendation></finding></xsl:if>
    
</xsl:template>


<xsl:template match="system.webServer">

  <!-- asp -->
  <xsl:if test="asp"><finding>system.webServer/asp Classic ASP is configured.<recommendation>Remove Classic ASP and it's support</recommendation></finding></xsl:if>
  <xsl:if test="asp[@scriptErrorSentToBrowser='true']"><finding>system.webServer/asp/@scriptErrorSentToBrowser is sending errors to the user agent.<recommendation>Remove Classic ASP and it's support</recommendation></finding></xsl:if>


  <!-- directoryBrowse -->
  <xsl:if test="directoryBrowse[@enabled='true']"><finding>system.webServer/directoryBrowse/@enabled is enabled.<recommendation>Set to false</recommendation></finding></xsl:if>


  <!-- defaultDocument -->
  <xsl:if test="defaultDocument/files/add and not(defaultDocument[@enabled='false']) and defaultDocument/files[count(./add) &gt; 4]"><finding class="warning">system.webServer/defaultDocument/files defines a large number of default documents.</finding></xsl:if>
  <xsl:if test="defaultDocument/files/add and not(defaultDocument[@enabled='false']) and defaultDocument/files/add[@value='iisstart.htm']"><finding class="warning">system.webServer/defaultDocument/files includes the server default iisstart.htm.<recommendation>Remove iisstart.htm</recommendation></finding></xsl:if>


  <!-- handlers -->
  <xsl:if test="handlers/add[@path='glimpse.axd']"><finding class="warning">system.webServer/handlers defines the use of glimpse for debugging.</finding></xsl:if>
  <xsl:if test="handlers/add[@path='elmah.axd']"><finding class="warning">system.webServer/handlers defines the use of ELMAH for debugging.</finding></xsl:if>

  <xsl:if test="handlers/add[@verb='*']"><finding>system.webServer/handlers defines wildcard verbs.<recommendation>Explicitly list all verbs to be used for each hander, e.g. 'GET,HEAD,POST'.</recommendation></finding></xsl:if>


  <!-- httpErrors -->
  <xsl:if test="not(httpErrors)"><finding>system.web/httpErrors is not defined.<recommendation>Provide custom error pages from the application.</recommendation></finding></xsl:if>
  <xsl:if test="httpErrors">
    <xsl:if test="httpErrors[@errorMode='Detailed']"><finding>system.web/httpErrors/@errorMode is set to emit detailed errors.<recommendation>Do not emit detailed error messages.</recommendation></finding></xsl:if>
    <xsl:if test="httpErrors[@errorMode='DetailedLocalOnly']"><finding class="warning">system.web/httpErrors/@errorMode is set to emit detailed errors locally.<recommendation>Do not emit detailed error messages and do not debug on the server.</recommendation></finding></xsl:if>

    <xsl:if test="httpErrors/clear and not(httpErrors/error[@statusCode='404'])"><finding>system.web/httpErrors/add does not define an error status for error 404.<recommendation>Define an error page for error 404.</recommendation></finding></xsl:if>
    <xsl:if test="httpErrors/clear and not(httpErrors/error[@statusCode='500'])"><finding>system.web/httpErrors/add does not define an error status for error 500.<recommendation>Define an error page for error 500.</recommendation></finding></xsl:if>

  </xsl:if>


  <!-- httpProtocol -->
  <xsl:if test="not(httpProtocol/customHeaders)"><finding>system.webServer/httpProtocol/customHeaders is not defined.<recommendation>Use the customHeaders section to set appropriate headers.</recommendation></finding></xsl:if>

  <xsl:if test="httpProtocol/customHeaders">
    <xsl:if test="not(httpProtocol/customHeaders/clear) and not(httpProtocol/customHeaders/remove[@name='X-Powered-By'])"><finding>system.webServer/httpProtocol/customHeaders doesn't remove the X-Powered-By header.<recommendation>Explicitly remove X-Powered-By.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/clear) and not(httpProtocol/customHeaders/remove[@name='X-AspNet-Version'])"><finding>system.webServer/httpProtocol/customHeaders doesn't remove the X-AspNet-Version header.<recommendation>Explicitly remove X-AspNet-Version.</recommendation></finding></xsl:if>
    <!-- Look for the removal of the MVC vresion only if MVC is enabled -->
    <xsl:if test="../system.web/pages/namespaces/add[@namespace='System.Web.Mvc'] and not(httpProtocol/customHeaders/clear) and not(httpProtocol/customHeaders/remove[@name='X-AspNetMvc-Version'])"><finding>system.webServer/httpProtocol/customHeaders doesn't remove the X-AspNetMvc-Version header.<recommendation>If MVC is in use, explicitly remove X-AspNetMvc-Version.</recommendation></finding></xsl:if>

    <xsl:if test="not(httpProtocol/customHeaders/add[@name='Content-Security-Policy'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the Content-Security-Policy header.<recommendation>Set a Content-Security-Policy.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='X-Content-Security-Policy'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the X-Content-Security-Policy header.<recommendation>Set a Content-Security-Policy.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='Expect-CT'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the Expect-CT header.<recommendation>Set a Expect-CT.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='Feature-Policy'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the Feature-Policy header.<recommendation>Set a Feature-Policy.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='Referrer-Policy'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the Referrer-Policy header.<recommendation>Set a Referrer-Policy.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='Strict-Transport-Security'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the Strict-Transport-Security header.<recommendation>Set a Strict-Transport-Security.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='X-Content-Type-Options'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the X-Content-Type-Options header.<recommendation>Set a X-Content-Type-Options.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='X-Frame-Options'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the X-Frame-Options header.<recommendation>Set a X-Frame-Options.</recommendation></finding></xsl:if>
    <xsl:if test="not(httpProtocol/customHeaders/add[@name='X-XSS-Protection'])"><finding>system.webServer/httpProtocol/customHeaders doesn't set the X-XSS-Protection header.<recommendation>Set a X-XSS-Protection.</recommendation></finding></xsl:if>

    <xsl:if test="httpProtocol/customHeaders/add[@name='P3P']"><finding>system.webServer/httpProtocol/customHeaders sets the deprecated P3P header.<recommendation>Do not set a P3P header.</recommendation></finding></xsl:if>
    <xsl:if test="httpProtocol/customHeaders/add[@name='Access-Control-Allow-Origin'][@value='*']"><finding>system.webServer/httpProtocol/customHeaders sets a poor Access-Control-Allow-Origin header.<recommendation>Limit to the required endpoints or remove, unless the site is a content delivery network serving unknown parties.</recommendation></finding></xsl:if>
    <xsl:if test="httpProtocol/customHeaders/add[@name='Access-Control-Allow-Methods'][contains(@value, 'TRACE')]"><finding>system.webServer/httpProtocol/customHeaders allows Access-Control-Allow-Methods with TRACE.<recommendation>Remove unnecessary CORS methods.</recommendation></finding></xsl:if>
    <xsl:if test="httpProtocol/customHeaders/add[@name='Access-Control-Allow-Methods'][contains(@value, 'DEBUG')]"><finding>system.webServer/httpProtocol/customHeaders allows Access-Control-Allow-Methods with DEBUG.<recommendation>Remove unnecessary CORS methods.</recommendation></finding></xsl:if>
  </xsl:if>

  <!-- OdbcLogging -->
  <xsl:if test="odbcLogging"><finding class="warning">system.webServer/odbcLogging is enabled.<recommendation>Log to files and asynchronously process to take advantage of kernel-mode caching and as per Microsoft warning.</recommendation></finding></xsl:if>

  <xsl:if test="odbcLogging/@password">
    <xsl:call-template name="keyValuePassword">
      <xsl:with-param name="area">system.webServer/odbcLogging/@password </xsl:with-param>
      <xsl:with-param name="key">password</xsl:with-param>    <!-- tell the template that this is a password to allow reuse -->
      <xsl:with-param name="value"><xsl:value-of select="odbcLogging/@password" /></xsl:with-param>
    </xsl:call-template>
  </xsl:if>


  <!-- security -->
  <xsl:if test="not (security/requestFiltering)"><finding>system.webServer/security/requestFiltering is not defined.<recommendation>Set requestFiltering to manage headers and supported verbs.</recommendation></finding></xsl:if>

  <xsl:if test="security/requestFiltering">
    <xsl:if test="security/requestFiltering[@allowDoubleEscaping='true']"><finding>system.webServer/security/requestFiltering/@allowDoubleEscaping is set.<recommendation>Disable request filtering.</recommendation></finding></xsl:if>
    <xsl:if test="security/requestFiltering[@allowHighBitCharacters='true']"><finding>system.webServer/security/requestFiltering/@allowHighBitCharacters is set.<recommendation>Disable high bit characters.</recommendation></finding></xsl:if>
    <xsl:if test="not(security/requestFiltering/@allowDoubleEscaping) or security/requestFiltering[@removeServerHeader='false']"><finding class="warning">system.webServer/security/requestFiltering/@removeServerHeader is not set.<recommendation>Set the removeServerHeader, if IIS 10 is in use.</recommendation></finding></xsl:if>

    <xsl:if test="security/requestFiltering/hiddenSegments/clear or security/requestFiltering/hiddenSegments/remove"><finding>system.webServer/security/requestFiltering/hiddenSegments has removed some hidden locations.<recommendation>Validate the removed locations are not used, and consider reinstating for defence in depth.</recommendation></finding></xsl:if>

    <xsl:if test="not(security/requestFiltering/verbs)"><finding>system.webServer/security/requestFiltering/verbs is not specified.<recommendation>Directly manage supported verbs.</recommendation></finding></xsl:if>

    <xsl:if test="security/requestFiltering/verbs[@allowUnlisted='true']"><finding>system.webServer/security/requestFiltering/verbs/@allowUnlisted is enabled.<recommendation>Disable processing of unexpected verbs.</recommendation></finding></xsl:if>
    <xsl:if test="security/requestFiltering/verbs[@applyToWebDAV='false']"><finding>system.webServer/security/requestFiltering/verbs/@applyToWebDAV is disabled.<recommendation>Disable WebDAV if possible, otherwise identify verbs required.</recommendation></finding></xsl:if>

    <xsl:if test="(security/requestFiltering/verbs/clear and security/requestFiltering/verbs/add[@verb='DEBUG'])
      and not (security/requestFiltering/verbs/remove[@verb='DEBUG'])"><finding>system.webServer/security/requestFiltering/verbs does not remove DEBUG.<recommendation>Remove the default DEBUG verb.</recommendation></finding></xsl:if>
    <xsl:if test="(security/requestFiltering/verbs/clear and security/requestFiltering/verbs/add[@verb='TRACE'])
      and not (security/requestFiltering/verbs/remove[@verb='TRACE'])"><finding>system.webServer/security/requestFiltering/verbs does not remove TRACE.<recommendation>Remove the default TRACE verb.</recommendation></finding></xsl:if>   
   
  </xsl:if>


  <!-- validation -->
  <xsl:if test="validation[@validateIntegratedModeConfiguration='false']"><finding>system.webServer/validation/@validateIntegratedModeConfiguration is disabled.<recommendation>Migrate settings to the IIS7+ method and then enable this or remove the element.</recommendation></finding></xsl:if>

</xsl:template>



<!-- ================ -->
<!-- Helper functions -->
<!-- ================ -->

<!-- Identify password and password-like information in key/value pairs -->
<xsl:template name="keyValuePassword">
  <xsl:param name="area" />
  <xsl:param name="key" />
  <xsl:param name="value" />

  <!-- Lowwecase the key and value due to repeated use -->
  <xsl:variable name="keyLower" select="translate($key, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')" /> 
  <xsl:variable name="valueLower" select="translate($value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')" /> 

  <!-- DSS requires hidden passwords in configuration files -->
  <xsl:if test="not(starts-with($valueLower,'[enc:'))"> <!-- passwords can, in some cases, be in the form [enc:AesProvider:57686f6120447564652c2049495320526f636b73:enc]" which is encrypted -->
    <xsl:if test="contains($keyLower, 'password')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> may contain a password in a readable form.</finding></xsl:if>
    <xsl:if test="contains($keyLower, 'passphrase')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> may contain a passphrase in a readable form.</finding></xsl:if>
    <xsl:if test="contains($keyLower, 'secret')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> may contain a 'secret' value in a readable form.</finding></xsl:if>
    <xsl:if test="contains($keyLower, 'hidden')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> may contain a 'hidden' value in a readable form.</finding></xsl:if>
    <xsl:if test="contains($keyLower, 'securitydata')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> may contain a 'securitydata' value in a readable form.</finding></xsl:if>
    <!-- last three have been seen in production systems, possibly to hide detection of the use of an insecure password? -->
  </xsl:if>

  <xsl:if test="contains($keyLower, 'password') and string-length($value) &lt; 8"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> password is very short.<recommendation>Set passwords of at least 16 characters in length when they don't need to change frequently</recommendation></finding></xsl:if>
  <xsl:if test="contains($keyLower, 'passphrase') and string-length($value) &lt; 8"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> passphrase is very short.<recommendation>Set passwords of at least 16 characters in length when they don't need to change frequently</recommendation></finding></xsl:if>
  <!-- NIST minimum lengths -->

  <xsl:if test="contains($keyLower, 'password') and string-length($value) &gt; 7 and string-length($value) &lt; 16"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> password is short.<recommendation>Set passwords of at least 16 characters in length when they don't need to change frequently</recommendation></finding></xsl:if>
  <xsl:if test="contains($keyLower, 'passphrase') and string-length($value) &gt; 7 and string-length($value) &lt; 16"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> passphrase is short.<recommendation>Set passwords of at least 16 characters in length when they don't need to change frequently</recommendation></finding></xsl:if>
  <!-- 'Sensible' minimum lengths -->

  <!-- appsettings can be used to set connection strings, URLs and similar with passwords in -->
  <xsl:if test="contains($valueLower, 'password')"><finding><xsl:value-of select="$area" /><xsl:value-of select="$key" /> contains a password in a readable form.</finding></xsl:if>
</xsl:template>

</xsl:stylesheet>