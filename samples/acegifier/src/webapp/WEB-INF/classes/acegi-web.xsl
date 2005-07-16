<?xml version="1.0" encoding="UTF-8"?>

<!-- 
 | XSL Sheet used by the web.xml to acegi-security beans converter
 | to create the new acegified web.xml.
 | $Id$
 -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<!-- The CAS proxy url (left empty if not to be used) -->
<xsl:param name="cas-proxy-url"/>
<!-- The acegi context file name - used in the -->
<xsl:param name="acegi-security-context-file" select="'applicationContext-acegi-security.xml'"/>

<xsl:output doctype-public="-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
        doctype-system="http://java.sun.com/dtd/web-app_2_3.dtd"
        indent="yes"/>

<!-- Identity template which we override for specific cases -->
<xsl:template match="@*|node()">
    <xsl:copy>
        <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
</xsl:template>
    
<xsl:template match="web-app">
<web-app>
    <xsl:apply-templates select="icon|display-name|description|distributable"/>  
    <xsl:apply-templates select="context-param"/>
    <xsl:call-template name="insert-spring-context-param"/>
    <xsl:if test="$cas-proxy-url">
	<!-- Required for CAS ProxyTicketReceptor servlet. This is the
	     URL to CAS' "proxy" actuator, where a PGT and TargetService can
	     be presented to obtain a new proxy ticket. THIS CAN BE
	     REMOVED IF THE APPLICATION DOESN'T NEED TO ACT AS A PROXY -->
    <context-param>
        <param-name>edu.yale.its.tp.cas.proxyUrl</param-name>
        <param-value><xsl:value-of select="$cas-proxy-url"/></param-value>
    </context-param>
    <xsl:text>&#xA;&#xA;</xsl:text>
    </xsl:if>

    <filter>
        <filter-name>Acegi Filter Chain Proxy</filter-name>
        <filter-class>net.sf.acegisecurity.util.FilterToBeanProxy</filter-class>
        <init-param>
            <param-name>targetClass</param-name>
            <param-value>net.sf.acegisecurity.util.FilterChainProxy</param-value>
        </init-param>
    </filter>
    <xsl:text>&#xA;&#xA;</xsl:text>

    <xsl:apply-templates select="filter"/>   
    
  <filter-mapping>
    <filter-name>Acegi Filter Chain Proxy</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <xsl:text>&#xA;&#xA;</xsl:text>
    
  <xsl:apply-templates select="filter-mapping"/>

  <!-- Only add a spring context loader listener if there isn't one there already -->
  <xsl:if test="not(./listener/listener-class[string()='org.springframework.web.context.ContextLoaderListener'])">
	<listener>
		<listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
	</listener>
  <xsl:text>&#xA;&#xA;</xsl:text>
  </xsl:if>

  <xsl:apply-templates select="listener"/>
    
  <!-- Run any remaining non-security elements through the identity template -->
  <xsl:apply-templates select="servlet|servlet-mapping|session-config|mime-mapping|welcome-file-list|error-page|taglib|resource-env-ref|resource-ref|env-entry|ejb-ref|ejb-local-ref"/>
    
</web-app>
</xsl:template>

<!-- 
 | Looks for the case where we have an existing Spring context and appends
 | the acegi file to the list of app. context files. Otherwise just copies the contents.
 -->
<xsl:template match="context-param">
    <context-param>
    <xsl:choose>
        <xsl:when test="./param-name = 'contextConfigLocation'">
            <param-name>contextConfigLocation</param-name>
            <param-value>
                <xsl:value-of select="./param-value"/>
                <xsl:value-of select="concat('    /WEB-INF/',$acegi-security-context-file)"/><xsl:text>&#xA;      </xsl:text>                
            </param-value>
        </xsl:when>
        <xsl:otherwise>
            <xsl:apply-templates />
        </xsl:otherwise>
    </xsl:choose>
    </context-param>
    <xsl:text>&#xA;&#xA;</xsl:text>
</xsl:template>

<!-- 
 | Inserts a Spring config location context-param if one doesn't already exist.
 | If there is one, do nothing as it will be handled by the context-param template above.
 --> 
<xsl:template name="insert-spring-context-param">
    <xsl:if test="not(./context-param/param-name[string() = 'contextConfigLocation'])">
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>
            <xsl:value-of select="concat('/WEB-INF/',$acegi-security-context-file)"/><xsl:text>&#xA;</xsl:text>
        </param-value>
    </context-param>
    <xsl:text>&#xA;&#xA;</xsl:text>
    </xsl:if>
</xsl:template>
    
</xsl:stylesheet>
