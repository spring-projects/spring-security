/**
 * 
 */
package org.springframework.security.config;

import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
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

		return definition;
	}

	private void setPropertyIfAvailable(Element element, String attribute, String property,
			RootBeanDefinition definition) {
		String propertyValue = element.getAttribute(attribute);
		if (StringUtils.hasText(propertyValue)) {
			definition.getPropertyValues().addPropertyValue(property, propertyValue);
		}
	}

	protected static RootBeanDefinition createBeandefinitionWithDefaults(ParserContext parserContext, RootBeanDefinition authenticationManager, RootBeanDefinition rememberMeServices) {
		RootBeanDefinition definition = new RootBeanDefinition(AuthenticationProcessingFilter.class);
		definition.getPropertyValues().addPropertyValue("authenticationManager",authenticationManager);
		definition.getPropertyValues().addPropertyValue("rememberMeServices",rememberMeServices);
//		RootBeanDefinition beanDefinition = AuthenticationMechanismBeanDefinitionParser.createAndRegisterBeanDefinitionWithDefaults(parserContext);
//		definition.getPropertyValues().addPropertyValue("authenticationManager",
//				parserContext.getReaderContext().getRegistry().getBeanDefinition(beanDefinition.getBeanClassName()));
//		definition.getPropertyValues().addPropertyValue("rememberMeServices",
//				RememberMeServicesBeanDefinitionParser.createAndRegisterBeanDefintionWithDefaults(parserContext));
		/* TODO: There should not be any defaults for these urls ?!?! */
		definition.getPropertyValues().addPropertyValue("authenticationFailureUrl", "/acegilogin.jsp?login_error=1");
		definition.getPropertyValues().addPropertyValue("defaultTargetUrl", "/");
		
		return definition;
	}

}
