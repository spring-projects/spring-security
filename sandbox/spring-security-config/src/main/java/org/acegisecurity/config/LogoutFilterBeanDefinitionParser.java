/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.logout.LogoutFilter;
import org.acegisecurity.ui.logout.SecurityContextLogoutHandler;
import org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author vpuri
 * @since
 */
public class LogoutFilterBeanDefinitionParser extends AbstractBeanDefinitionParser {

	// ~ Instance fields
	// ================================================================================================
	private static final String REDIRECT_AFTER_LOGOUT_URL = "redirectAfterLogoutUrl";

	private static final String LOGOUT_URL = "logoutUrl";

	private static final String REDIRECT_AFTER_LOGOUT_URL_VALUE = "/";

	// ~ Methods
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		// add the properties
		RootBeanDefinition definition = new RootBeanDefinition(LogoutFilter.class);
		doCreateBeanDefinition(definition, element, parserContext, false);
		return definition;
	}

	/**
	 * 
	 * @param definition
	 * @param element
	 * @param parserContext
	 * @param isAutoconfig
	 * @see {@link AutoConfigBeanDefinitionParser}
	 */
	private void doCreateBeanDefinition(RootBeanDefinition definition, Element element, ParserContext parserContext,
			boolean isAutoconfig) {

		setConstructorArgumentIfAvailable(0, element, REDIRECT_AFTER_LOGOUT_URL, "logoutSuccessUrl", definition);
		setPropertyIfAvailable(element, LOGOUT_URL, "filterProcessesUrl", definition);
		/* TODO: Move this logic to LogoutFilter itlself */
		// register BFPP to check if LogoutFilter does not have setHandlers
		// populated, introspect app ctx for LogoutHandlers, using Ordered
		// (if
		// present, otherwise assume Integer.MAX_VALUE)
		RootBeanDefinition bfpp = new RootBeanDefinition(LogoutHandlerOrderResolver.class);
		parserContext.getReaderContext().registerWithGeneratedName(bfpp);

	}

	private void setConstructorArgumentIfAvailable(int index, Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			addConstructorArgument(index, definition, propertyValue);
		}
	}

	private void addConstructorArgument(int index, RootBeanDefinition definition, String propertyValue) {
		definition.getConstructorArgumentValues().addIndexedArgumentValue(index, propertyValue);
	}

	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}

	/**
	 * Creates <code>BeanDefintion</code> as required by 'autoconfig' tag
	 * 
	 * @param definition The BeanDefinition for Logoutfilter
	 * @param element
	 * @param parserContext
	 * @param isAutoconfig
	 * @return definition
	 */
	protected static RootBeanDefinition createBeanDefinitionWithDefaults(RootBeanDefinition rememberMeServices) {
		RootBeanDefinition definition = new RootBeanDefinition(LogoutFilter.class);
		definition.getConstructorArgumentValues().addIndexedArgumentValue(0, REDIRECT_AFTER_LOGOUT_URL_VALUE);
		// create BeanDefinitions for LogoutHandlers
		// (TokenBasedRememberMeServices) and (SecuritycontextLogoutHandler)
		ManagedList handlers = new ManagedList();
		//RootBeanDefinition rememberMeServices = RememberMeServicesBeanDefinitionParser.doCreateBeanDefintionWithDefaults();
		handlers.add(rememberMeServices);
		handlers.add(new RootBeanDefinition(SecurityContextLogoutHandler.class));
		definition.getConstructorArgumentValues().addIndexedArgumentValue(1, handlers);
		return definition;
	}

}
