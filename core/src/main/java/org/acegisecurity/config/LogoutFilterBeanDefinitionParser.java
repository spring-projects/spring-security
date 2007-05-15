/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.logout.LogoutFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
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

	// ~ Methods
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		// add the properties
		RootBeanDefinition definition = new RootBeanDefinition(LogoutFilter.class);
		setConstructorArgumentIfAvailable(0, element, REDIRECT_AFTER_LOGOUT_URL, "logoutSuccessUrl", definition);
		// setPropertyIfAvailable(element,
		// element.getAttribute(REDIRECT_AFTER_LOGOUT_URL), "logoutSuccessUrl",
		// definition);
		setPropertyIfAvailable(element, LOGOUT_URL, "filterProcessesUrl", definition);

		// register BFPP to check if LogoutFilter does not have setHandlers
		// populated, introspect app ctx for LogoutHandlers, using Ordered (if
		// present, otherwise assume Integer.MAX_VALUE)
		RootBeanDefinition bfpp = new RootBeanDefinition(LogoutHandlerOrderResolver.class);
		parserContext.getReaderContext().registerWithGeneratedName(bfpp);

		return definition;
	}

	private void setConstructorArgumentIfAvailable(int index, Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getConstructorArgumentValues().addIndexedArgumentValue(index, propertyValue);
		}
	}

	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}

	//

}
