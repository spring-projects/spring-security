package org.springframework.security.ui.preauth.j2ee;

import java.io.InputStream;

import org.springframework.security.rolemapping.XmlMappableRolesRetriever;

/**
 * <p>
 * This MappableRolesRetriever implementation reads the list of defined J2EE
 * roles from a web.xml file. It's functionality is based on the
 * XmlMappableRolesRetriever base class.
 * </p>
 * 
 * <p>
 * Example on how to configure this MappableRolesRetriever in the Spring
 * configuration file:
 * 
 * <pre>
 * 
 *  
 *   	&lt;bean id=&quot;j2eeMappableRolesRetriever&quot; class=&quot;org.springframework.security.ui.preauth.j2ee.WebXmlMappableRolesRetriever&quot;&gt;
 *  		&lt;property name=&quot;webXmlInputStream&quot;&gt;&lt;bean factory-bean=&quot;webXmlResource&quot; factory-method=&quot;getInputStream&quot;/&gt;&lt;/property&gt;
 *  	&lt;/bean&gt;
 *  	&lt;bean id=&quot;webXmlResource&quot; class=&quot;org.springframework.web.context.support.ServletContextResource&quot;&gt;
 *  		&lt;constructor-arg&gt;&lt;ref local=&quot;servletContext&quot;/&gt;&lt;/constructor-arg&gt;
 *  		&lt;constructor-arg&gt;&lt;value&gt;/WEB-INF/web.xml&lt;/value&gt;&lt;/constructor-arg&gt;
 *  	&lt;/bean&gt;
 *  	&lt;bean id=&quot;servletContext&quot; class=&quot;org.springframework.web.context.support.ServletContextFactoryBean&quot;/&gt;
 *   
 *  
 * </pre>
 * 
 * </p>
 */
public class WebXmlMappableRolesRetriever extends XmlMappableRolesRetriever {
	private static final String XPATH_EXPR = "/web-app/security-role/role-name/text()";

	/**
	 * Constructor setting the XPath expression to use
	 */
	public WebXmlMappableRolesRetriever() {
		super.setXpathExpression(XPATH_EXPR);
	}

	/**
	 * @param anInputStream
	 *            The InputStream to read the XML data from
	 */
	public void setWebXmlInputStream(InputStream anInputStream) {
		super.setXmlInputStream(anInputStream);
	}
}
