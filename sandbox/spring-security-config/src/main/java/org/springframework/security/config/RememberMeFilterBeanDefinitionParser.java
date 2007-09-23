/**
 * 
 */
package org.springframework.security.config;

import org.springframework.security.ui.rememberme.RememberMeProcessingFilter;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author vpuri
 *
 *@since
 */
public class RememberMeFilterBeanDefinitionParser extends AbstractBeanDefinitionParser  {

	private static final String REMEMBER_ME_SERVICES_REF = "rememberMeServicesBeanRef";
	
	private static final String REMEMBER_ME_SERVICES = "rememberMeServices";

	
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		Assert.notNull(parserContext, "ParserContext must not be null");
		
		RootBeanDefinition rememberMeFilterBeanDef = new RootBeanDefinition(RememberMeProcessingFilter.class);
		// check if rememberMeServicesBeanRef is defined and if it's specified use its referred bean
		String rememberMeServicesRef = element.getAttribute(REMEMBER_ME_SERVICES_REF);
		if (StringUtils.hasLength(rememberMeServicesRef)) {
			rememberMeFilterBeanDef.getPropertyValues().addPropertyValue(REMEMBER_ME_SERVICES,
					new RuntimeBeanReference(rememberMeServicesRef));
		} 
		return rememberMeFilterBeanDef;
	}
	
	protected static RootBeanDefinition createBeanDefinitionWithDefaults(ParserContext parserContext, RootBeanDefinition authenticationManager) {
		RootBeanDefinition definition= new RootBeanDefinition(RememberMeProcessingFilter.class);
		definition.getPropertyValues().addPropertyValue("authenticationManager",authenticationManager);
		return definition;
	}
}
