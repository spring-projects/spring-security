<?xml version="1.0" encoding="UTF-8"?>

<!-- 
 | XSL Sheet used by the web.xml to acegi-security beans converter
 | $Id$
 -->


<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:output doctype-public="-//SPRING//DTD BEAN//EN"
            doctype-system="http://www.springframework.org/dtd/spring-beans.dtd"
            indent="yes"/>

<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'"/>
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'"/>    
    
<xsl:variable name="welcome-files" select="web-app/welcome-file-list/welcome-file"/>
<!-- convert the auth-method content to upper case -->
<xsl:variable name="auth-method" select="translate(string(web-app/login-config/auth-method), $lowercase, $uppercase)"/>

<xsl:variable name="all-roles">
    <xsl:for-each select="web-app/security-role/role-name">
        <xsl:text>ROLE_</xsl:text>
        <xsl:value-of select="translate(string(), $lowercase, $uppercase)"/>           
        <xsl:if test="position() != last()">,</xsl:if>
    </xsl:for-each>    
</xsl:variable>

<!-- The list of filters for use in filterToBeanProxy -->
<xsl:variable name="filter-list">
<xsl:text>/**=httpSessionContextIntegrationFilter</xsl:text>
<xsl:choose>
    <xsl:when test="$auth-method = 'FORM'">
        <xsl:text>,authenticationProcessingFilter</xsl:text>
    </xsl:when>
    <xsl:when test="$auth-method = 'BASIC'">
        <xsl:text>,basicProcessingFilter</xsl:text>
    </xsl:when>
    <xsl:otherwise>
        <xsl:message terminate="yes">Unsupported auth-method in web.xml, must be FORM or BASIC</xsl:message>
    </xsl:otherwise>
</xsl:choose>
<xsl:text>,rememberMeProcessingFilter,anonymousProcessingFilter,securityEnforcementFilter</xsl:text>
</xsl:variable>
    
    
    
<xsl:template match = "web-app">

<beans>
    <xsl:call-template name="filter-to-bean-proxy"/>
    <xsl:call-template name="authentication-beans"/>
    
    <xsl:apply-templates select="./login-config"/>
    <xsl:call-template name="filter-invocation-interceptor"/>
</beans>
</xsl:template>

<xsl:template name="authentication-beans">
    <xsl:comment>======================== AUTHENTICATION =======================</xsl:comment>
    
    <bean id="authenticationManager" class="net.sf.acegisecurity.providers.ProviderManager">
      <property name="providers">
         <list>
            <ref local="daoAuthenticationProvider"/>
            <ref local="anonymousAuthenticationProvider"/>
             <ref local="rememberMeAuthenticationProvider"/>
         </list>
      </property>
    </bean>
   
    <bean id="daoAuthenticationProvider" class="net.sf.acegisecurity.providers.dao.DaoAuthenticationProvider">
      <property name="authenticationDao"><ref local="inMemoryDaoImpl"/></property>
      <!-- property name="userCache"><ref local="userCache"/></property-->
    </bean>

    <bean id="inMemoryDaoImpl" class="net.sf.acegisecurity.providers.dao.memory.InMemoryDaoImpl">
        <property name="userMap">
            <value>    
              superuser=password,<xsl:value-of select="$all-roles"/>
              <xsl:text>&#xA;</xsl:text>
            </value>
        </property>
    </bean>
    
    <bean id="anonymousProcessingFilter" class="net.sf.acegisecurity.providers.anonymous.AnonymousProcessingFilter">
      <property name="key"><value>foobar</value></property>
      <property name="userAttribute"><value>anonymousUser,ROLE_ANONYMOUS</value></property>
    </bean>
    
    <bean id="anonymousAuthenticationProvider" class="net.sf.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider">
      <property name="key"><value>foobar</value></property>
    </bean>
    
    <bean id="httpSessionContextIntegrationFilter" class="net.sf.acegisecurity.context.HttpSessionContextIntegrationFilter">
    </bean>
    
    <bean id="rememberMeProcessingFilter" class="net.sf.acegisecurity.ui.rememberme.RememberMeProcessingFilter">
      <property name="rememberMeServices"><ref local="rememberMeServices"/></property>
    </bean>
    
    <bean id="rememberMeServices" class="net.sf.acegisecurity.ui.rememberme.TokenBasedRememberMeServices">
      <property name="authenticationDao"><ref local="inMemoryDaoImpl"/></property>
      <property name="key"><value>springRocks</value></property>
    </bean>
    
    <bean id="rememberMeAuthenticationProvider" class="net.sf.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider">
      <property name="key"><value>springRocks</value></property>
    </bean>    
</xsl:template>

<!-- login configuration -->
<xsl:template match="login-config">
    <xsl:call-template name="security-enforcement-filter"/>
    <xsl:choose>
        <xsl:when test="$auth-method = 'FORM'">
            <xsl:call-template name="form-login"/>
        </xsl:when>
        <xsl:when test="$auth-method = 'BASIC'">
   <bean id="basicProcessingFilter" class="net.sf.acegisecurity.ui.basicauth.BasicProcessingFilter">
      <property name="authenticationManager"><ref local="authenticationManager"/></property>
      <property name="authenticationEntryPoint"><ref local="basicProcessingFilterEntryPoint"/></property>
   </bean>

   <bean id="basicProcessingFilterEntryPoint" class="net.sf.acegisecurity.ui.basicauth.BasicProcessingFilterEntryPoint">
      <property name="realmName"><value>Your Realm</value></property>
   </bean>                
        </xsl:when>
    </xsl:choose>
            
</xsl:template>

<!-- 
 | Inserts the security enforcement filter bean with the appropriate entry point 
 | (depending on whether FORM or BASIC authentication is selected in web.xml). 
 -->    
<xsl:template name="security-enforcement-filter">
   <bean id="securityEnforcementFilter" class="net.sf.acegisecurity.intercept.web.SecurityEnforcementFilter">
      <property name="filterSecurityInterceptor"><ref local="filterInvocationInterceptor"/></property>
      <property name="authenticationEntryPoint">
    <xsl:choose>
        <xsl:when test="$auth-method = 'FORM'">
      <ref local="authenticationProcessingFilterEntryPoint"/>
        </xsl:when>
        <xsl:when test="$auth-method = 'BASIC'">
      <ref local="basicProcessingFilterEntryPoint"/>              
        </xsl:when>
    </xsl:choose>
      </property>
   </bean>
</xsl:template>
    
<!--
 | Outputs a standard filterToBeanProxy bean.
 -->
<xsl:template name="filter-to-bean-proxy">
    <xsl:comment>======================== FILTER CHAIN =======================</xsl:comment>

	<xsl:comment>if you wish to use channel security, add "channelProcessingFilter," in front
	      of "httpSessionContextIntegrationFilter" in the list below</xsl:comment>
	<bean id="filterChainProxy" class="net.sf.acegisecurity.util.FilterChainProxy">
      <property name="filterInvocationDefinitionSource">
         <value>
            CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON
            PATTERN_TYPE_APACHE_ANT
            <xsl:value-of select="$filter-list"/>
         </value>
      </property>
	</bean>

</xsl:template>
    
<!-- 
    Converts a form login configuration to an Acegi AuthenticationProcessingFilter and its entry point.
    The content of the form-login-page element is used for the loginFormUrl property of the entry point 
    and the form-error-page is used for the authenticationFailureUrl property of the filter.
    
    The user must manually change the form Url to "j_acegi_security_check"
 -->
    <xsl:template name="form-login">
        <xsl:message>Processing form login configuration</xsl:message>
        <xsl:message>Remember to switch your login form action from "j_security_check" to "j_acegi_security_check"</xsl:message>       
        
   <bean id="authenticationProcessingFilter" class="net.sf.acegisecurity.ui.webapp.AuthenticationProcessingFilter">
      <property name="authenticationManager"><ref bean="authenticationManager"/></property>
      <property name="authenticationFailureUrl"><value><xsl:value-of select="form-login-config/form-error-page"/></value></property>
      <property name="defaultTargetUrl"><value></value></property>
      <property name="filterProcessesUrl"><value>/j_acegi_security_check</value></property>
      <property name="rememberMeServices"><ref local="rememberMeServices"/></property>
   </bean>

   <bean id="authenticationProcessingFilterEntryPoint" class="net.sf.acegisecurity.ui.webapp.AuthenticationProcessingFilterEntryPoint">
      <property name="loginFormUrl"><value><xsl:value-of select="form-login-config/form-login-page"/></value></property>
      <property name="forceHttps"><value>false</value></property>
   </bean> 
        
    </xsl:template>
    
    <xsl:template name="filter-invocation-interceptor">
        <bean id="httpRequestAccessDecisionManager" class="net.sf.acegisecurity.vote.AffirmativeBased">
            <property name="allowIfAllAbstainDecisions"><value>false</value></property>
            <property name="decisionVoters">
                <list>
                    <ref bean="roleVoter"/>
                </list>
            </property>
        </bean>
        
       <!-- An access decision voter that reads ROLE_* configuration settings -->
        <bean id="roleVoter" class="net.sf.acegisecurity.vote.RoleVoter"/>        
        
        <xsl:text>&#xA;</xsl:text>
       <xsl:comment> 
       Note the order that entries are placed against the objectDefinitionSource is critical.
       The FilterSecurityInterceptor will work from the top of the list down to the FIRST pattern that matches the request URL.
       Accordingly, you should place MOST SPECIFIC (ie a/b/c/d.*) expressions first, with LEAST SPECIFIC (ie a/.*) expressions last
       </xsl:comment>
        <bean id="filterInvocationInterceptor" class="net.sf.acegisecurity.intercept.web.FilterSecurityInterceptor">
          <property name="authenticationManager"><ref bean="authenticationManager"/></property>
          <property name="accessDecisionManager"><ref local="httpRequestAccessDecisionManager"/></property>
          <property name="objectDefinitionSource">
             <value>
                <xsl:text>&#xA;CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON&#xA;</xsl:text>                 
                <xsl:text>PATTERN_TYPE_APACHE_ANT&#xA;</xsl:text>
                <xsl:apply-templates select="security-constraint"/>
             </value>
          </property>
        </bean>        
    </xsl:template>
    
    <xsl:template match="security-constraint">
        <xsl:value-of select="web-resource-collection/url-pattern"/>
        <xsl:text>=</xsl:text>
        <xsl:for-each select="./auth-constraint/role-name">
            <xsl:choose>
                <xsl:when test="string() = '*'">
                    <xsl:value-of select="$all-roles"/>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:text>ROLE_</xsl:text>
                    <xsl:value-of select="translate(string(), $lowercase, $uppercase)"/>
                </xsl:otherwise>
            </xsl:choose>
            <xsl:if test="position() != last()">,</xsl:if>
        </xsl:for-each>
        <xsl:text>&#xA;</xsl:text>
    </xsl:template>

    <xsl:template name="list-roles">
        <xsl:for-each select="security-role/role-name">
            <xsl:text>ROLE_</xsl:text>
            <xsl:value-of select="translate(string(), $lowercase, $uppercase)"/>           
            <xsl:if test="position() != last()">,</xsl:if>
        </xsl:for-each>
    </xsl:template>    
    
</xsl:stylesheet>
