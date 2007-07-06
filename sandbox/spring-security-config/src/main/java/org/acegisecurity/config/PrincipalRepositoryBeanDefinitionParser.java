/**
 * 
 */
package org.acegisecurity.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.jdbc.JdbcDaoImpl;
import org.acegisecurity.userdetails.memory.InMemoryDaoImpl;
import org.acegisecurity.userdetails.memory.UserAttribute;
import org.acegisecurity.userdetails.memory.UserMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
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

	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory.getLog(PrincipalRepositoryBeanDefinitionParser.class);

	// ~ Instance fields
	// ================================================================================================
	private static final String JDBC = "jdbc";

	private static final String DATASOURCE_REF = "dataSourceBeanRef";

	private static final String DATASOURCE = "dataSource";

	private static final String JDBCTEMPLATE_REF = "jdbcTemplateBeanRef";

	private static final String JDBCTEMPLATE = "jdbcTemplate";

	private static final String AUTHORITIES_BY_USERNAME_QUERY = "authoritiesByUsernameQuery";

	private static final String ROLE_PREFIX = "rolePrefix";

	private static final String USERNAME_BASED_PRIMARY_KEY = "usernameBasedPrimaryKey";

	private static final String PROPERTIES = "properties";

	private static final String RESOURCE = "resource";

	private static final String USER_PROPERTIES = "userProperties";

	private static final String USER_DEFINITION = "user-definition";

	private static final Object GRANTED_AUTHORITY = "granted-authority";

	private static final String USERNAME = "username";

	private static final String PASSWORD = "password";

	private static final String ENABLED = "enabled";

	private static final String GRANTED_AUTHORITY_REF = "granted-authority-ref";

	private static final String AUTHORITY = "authority";

	private static final String AUTHORITY_BEAN_REF = "authorityBeanRef";

	// ~ Method
	// ================================================================================================
	/**
	 * 
	 */

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		NodeList userDetailsServiceChildren = element.getChildNodes();
		RootBeanDefinition userDetailsServiceDefinition = null;
		for (int i = 0, n = userDetailsServiceChildren.getLength(); i < n; i++) {
			Node userDetailsService = userDetailsServiceChildren.item(i);

			if (JDBC.equals(userDetailsService.getLocalName()) && userDetailsService.getNodeType() == Node.ELEMENT_NODE) {
				Element ele = (Element) userDetailsService;
				userDetailsServiceDefinition = parseUserDetailsServiceJdbcDefinition(ele);
				userDetailsServiceDefinition.setSource(parserContext.extractSource(element));
			}
			if (PROPERTIES.equals(userDetailsService.getLocalName())
					&& userDetailsService.getNodeType() == Node.ELEMENT_NODE) {
				Element ele = (Element) userDetailsService;

				userDetailsServiceDefinition = new RootBeanDefinition(InMemoryDaoImpl.class);
				userDetailsServiceDefinition.getPropertyValues().addPropertyValue(USER_PROPERTIES,
						new RuntimeBeanReference(createPropertiesBeanDefinition(ele, parserContext)));
				userDetailsServiceDefinition.setSource(parserContext.extractSource(element));
			}
			if (USER_DEFINITION.equals(userDetailsService.getLocalName())
					&& userDetailsService.getNodeType() == Node.ELEMENT_NODE) {
				Element ele = (Element) userDetailsService;

				// create a UserMap which interns uses UserMapEditor
				userDetailsServiceDefinition = createUserDefinition(ele, parserContext);
			}
		}
		return userDetailsServiceDefinition;
	}

	private RootBeanDefinition createUserDefinition(Element ele, ParserContext parserContext) {
		RootBeanDefinition definition = new RootBeanDefinition(InMemoryDaoImpl.class);

		UserAttribute userAttribute = new UserAttribute();
		UserMap userMap = new UserMap();

		setPassword(ele, userAttribute);
		setEnabled(ele, userAttribute);
		setAuthorities(ele, userAttribute);

		UserDetails user = new User(ele.getAttribute(USERNAME), userAttribute.getPassword(), userAttribute.isEnabled(),
				true, true, true, userAttribute.getAuthorities());
		userMap.addUser(user);
		definition.getPropertyValues().addPropertyValue("userMap", userMap);
		return definition;
	}

	private String createPropertiesBeanDefinition(Element ele, ParserContext parserContext) {
		// properties element
		RootBeanDefinition defintion = new RootBeanDefinition(PropertiesFactoryBean.class);
		String propertyValue = ele.getAttribute(RESOURCE);
		defintion.getPropertyValues().addPropertyValue("location", propertyValue);
		defintion.setSource(parserContext.extractSource(ele));
		return parserContext.getReaderContext().registerWithGeneratedName(defintion);
	}
	
	protected static RootBeanDefinition createSampleUsersUsingProperties() {
		// properties element
		RootBeanDefinition defintion = new RootBeanDefinition(PropertiesFactoryBean.class);
		String location = "classpath:org/acegisecurity/config/user.properties";
		defintion.getPropertyValues().addPropertyValue("location", location);
		return defintion;
	}
	

	/**
	 * 
	 * @param elementToParse
	 * @return
	 */
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

	protected void doParseProperties(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		Properties parsedProps = parserContext.getDelegate().parsePropsElement(element);
		builder.addPropertyValue(PROPERTIES, parsedProps);
	}

	/**
	 * 
	 * @param element
	 * @param attribute
	 * @param property
	 * @param definition
	 */
	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			if (propertyValue.equals(DATASOURCE_REF) || propertyValue.equals(JDBCTEMPLATE_REF)) {
				definition.getPropertyValues().addPropertyValue(property, new RuntimeBeanReference(propertyValue));
			}
			else {
				definition.getPropertyValues().addPropertyValue(property, propertyValue);
			}
		}
	}

	private void setPassword(Element element, UserAttribute userAttribute) {
		String propertyValue = element.getAttribute(PASSWORD);
		if (StringUtils.hasText(propertyValue)) {
			userAttribute.setPassword(propertyValue);
		}
	}

	private void setEnabled(Element element, UserAttribute userAttribute) {
		String propertyValue = element.getAttribute(ENABLED);
		if (StringUtils.hasText(propertyValue)) {
			if (propertyValue.equals("true")) {
				userAttribute.setEnabled(true);
			}
			else {
				userAttribute.setEnabled(false);
			}
		}
	}

	private void setAuthorities(Element ele, UserAttribute userAttribute) {
		// get authorities
		NodeList childNodes = ele.getChildNodes();

		ManagedList authorities = new ManagedList();

		for (int i = 0, n = childNodes.getLength(); i < n; i++) {
			Node authorityNode = childNodes.item(i);

			if (GRANTED_AUTHORITY.equals(authorityNode.getLocalName())
					&& authorityNode.getNodeType() == Element.ELEMENT_NODE) {
				Element propertyValue = (Element) authorityNode;
				authorities.add(new GrantedAuthorityImpl(propertyValue.getAttribute(AUTHORITY)));
			}

			if (GRANTED_AUTHORITY_REF.equals(authorityNode.getLocalName())
					&& authorityNode.getNodeType() == Element.ELEMENT_NODE) {
				Element propertyValue = (Element) authorityNode;
				String attribute = propertyValue.getAttribute(AUTHORITY_BEAN_REF);
				if (StringUtils.hasLength(attribute)) {
					authorities.add(new RuntimeBeanReference(attribute));
				}
			}
		}
		userAttribute.setAuthorities(authorities);
	}

}
