/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author vpuri
 *
 */
public class RememberMeServicesBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {
	
	private static final String PRINCIPAL_REPOSITORY_BEAN_REF = "principalRepositoryBeanRef";
	
	private static final String USER_DETAILS_SERVICE_PROPERTY = "userDetailsService";
	
	/*
	 * key is optional; if unspecified, pick a rnd int and use for all unspecified key properties for acegi beans
	 */
	private static final String KEY = "key";

	/**
	 * 
	 */
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		Assert.notNull(parserContext, "ParserContext must not be null");		
		
		RootBeanDefinition rememberMeServicesBeanDef = new RootBeanDefinition(TokenBasedRememberMeServices.class);
		
		String keyValue = element.getAttribute(KEY);
		if (StringUtils.hasLength(keyValue)) {
			rememberMeServicesBeanDef.getPropertyValues().addPropertyValue(KEY,keyValue);
		}  else {
			// pick a rnd int
		}
		
		//	 check if rememberMeServicesBeanRef is defined and if it's specified use its referred bean
		String rememberMeServicesRef = element.getAttribute(PRINCIPAL_REPOSITORY_BEAN_REF);
		if (StringUtils.hasLength(rememberMeServicesRef)) {
			rememberMeServicesBeanDef.getPropertyValues().addPropertyValue(USER_DETAILS_SERVICE_PROPERTY,
					new RuntimeBeanReference(rememberMeServicesRef));
		}  
		else {
			// register a bean definition parse
			RootBeanDefinition configurer = new RootBeanDefinition(RemeberMeServicesDependenciesConfigurer.class);
			parserContext.getReaderContext().registerWithGeneratedName(configurer);
		}
		return rememberMeServicesBeanDef;
	}

}
