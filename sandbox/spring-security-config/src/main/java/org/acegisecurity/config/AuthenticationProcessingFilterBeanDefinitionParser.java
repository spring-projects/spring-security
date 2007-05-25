/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author vpuri
 * 
 */
public class AuthenticationProcessingFilterBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {

	// ~ Instance fields
	// ================================================================================================

	private static final String AUTHENTICATION_URL = "authenticationUrl";

	private static final String ERROR_FORM_URL = "errorFormUrl";

	private static final String DEFAULT_TARGET_URL = "defaultTargetUrl";

	// ~ Methods
	// ================================================================================================

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		RootBeanDefinition definition = new RootBeanDefinition(AuthenticationProcessingFilter.class);

		setPropertyIfAvailable(element, AUTHENTICATION_URL, "filterProcessesUrl", definition);
		setPropertyIfAvailable(element, ERROR_FORM_URL, "authenticationFailureUrl", definition);
		setPropertyIfAvailable(element, DEFAULT_TARGET_URL, "defaultTargetUrl", definition);

		// register BFPP to re-unite all other collaborators
		RootBeanDefinition postProcessor = new RootBeanDefinition(
				AuthenticationProcessingFilterDependenciesConfigurer.class);
		parserContext.getReaderContext().registerWithGeneratedName(postProcessor);

		return definition;
	}

	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}

}
