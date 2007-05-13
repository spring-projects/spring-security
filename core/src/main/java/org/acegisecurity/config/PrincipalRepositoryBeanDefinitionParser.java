/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * @author vpuri
 * 
 */
public class PrincipalRepositoryBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	
	//	~ Instance fields ================================================================================================
	private static final String JDBC = "jdbc";
	private static final String DATASOURCE_REF = "dataSourceBeanRef";
	private static final String DATASOURCE = "dataSource";
	private static final String JDBCTEMPLATE_REF = "jdbcTemplateBeanRef";
	private static final String JDBCTEMPLATE = "jdbcTemplate";
	private static final String AUTHORITIES_BY_USERNAME_QUERY = "authoritiesByUsernameQuery";
	private static final String ROLE_PREFIX = "rolePrefix";
	private static final String USERNAME_BASED_PRIMARY_KEY="usernameBasedPrimaryKey";
	
	//authoritiesByUsernameQuery=""  rolePrefix="" usernameBasedPrimaryKey="true"  usersByUsernameQuery=""
	
	//	~ Method ================================================================================================
	
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		NodeList userDetailsServiceChildren = element.getChildNodes();
		RootBeanDefinition userDetailsServiceJdbcDefinition = null;
		for (int i = 0, n = userDetailsServiceChildren.getLength(); i < n; i++) {
			Node userDetailsService = userDetailsServiceChildren.item(i);

			if (JDBC.equals(userDetailsService.getLocalName()) && userDetailsService.getNodeType() == Node.ELEMENT_NODE) {
				Element ele = (Element) userDetailsService;
				userDetailsServiceJdbcDefinition = parseUserDetailsServiceJdbcDefinition(ele);
				userDetailsServiceJdbcDefinition.setSource(parserContext.extractSource(element));
				parserContext.getReaderContext().registerWithGeneratedName(userDetailsServiceJdbcDefinition);
			}
		}
		return userDetailsServiceJdbcDefinition;
	}

	private RootBeanDefinition parseUserDetailsServiceJdbcDefinition(Element elementToParse) {
		// parse attributes
		RootBeanDefinition definition = new RootBeanDefinition(JdbcDaoImpl.class);
		setPropertyIfAvailable(elementToParse, DATASOURCE_REF, DATASOURCE, definition);
		setPropertyIfAvailable(elementToParse, JDBCTEMPLATE_REF, JDBCTEMPLATE, definition);
		setPropertyIfAvailable(elementToParse, AUTHORITIES_BY_USERNAME_QUERY, AUTHORITIES_BY_USERNAME_QUERY, definition);
		setPropertyIfAvailable(elementToParse, ROLE_PREFIX, ROLE_PREFIX, definition);
		setPropertyIfAvailable(elementToParse, USERNAME_BASED_PRIMARY_KEY, USERNAME_BASED_PRIMARY_KEY, definition);
		return definition;
	}
	
	private void setPropertyIfAvailable(Element el, String attribute, String property, RootBeanDefinition definition) {
		String propertyValue = el.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(propertyValue));
		}
	}



}
