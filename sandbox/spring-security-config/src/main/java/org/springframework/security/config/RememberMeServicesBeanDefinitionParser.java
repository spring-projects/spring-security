/**
 * 
 */
package org.springframework.security.config;

import org.springframework.security.ui.rememberme.TokenBasedRememberMeServices;
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
 * Parses
 * @author vpuri
 * 
 */
public class RememberMeServicesBeanDefinitionParser extends AbstractBeanDefinitionParser implements
		BeanDefinitionParser {

	private static final String PRINCIPAL_REPOSITORY_BEAN_REF = "principalRepositoryBeanRef";

	private static final String USER_DETAILS_SERVICE_PROPERTY = "userDetailsService";

	/*
	 * key is optional; if unspecified, pick a rnd int and use for all
	 * unspecified key properties for acegi beans
	 */
	private static final String KEY = "key";

	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
		RootBeanDefinition rememberMeServicesBeanDef = createBeanDefinition(element, parserContext);
		return rememberMeServicesBeanDef;
	}

	private  RootBeanDefinition createBeanDefinition(Element element, ParserContext parserContext) {
		Assert.notNull(parserContext, "ParserContext must not be null");

		RootBeanDefinition rememberMeServicesBeanDef = new RootBeanDefinition(TokenBasedRememberMeServices.class);

		String keyValue = "";
		String rememberMeServicesRef = "";

		if (element != null) {
			keyValue = element.getAttribute(KEY);

			if (StringUtils.hasLength(keyValue)) {
				rememberMeServicesBeanDef.getPropertyValues().addPropertyValue(KEY, keyValue);
			}
			else {
				/*
				 * TODO: pick a rnd int and apply it whenver required in
				 * applicationcontext
				 */
				
			}

			// check if rememberMeServicesBeanRef is defined and if it's
			// specified
			// use its referred bean
			rememberMeServicesRef = element.getAttribute(PRINCIPAL_REPOSITORY_BEAN_REF);
			if (StringUtils.hasLength(rememberMeServicesRef)) {
				rememberMeServicesBeanDef.getPropertyValues().addPropertyValue(USER_DETAILS_SERVICE_PROPERTY,
						new RuntimeBeanReference(rememberMeServicesRef));
			}
		}

		return rememberMeServicesBeanDef;
	}
	
	protected static RootBeanDefinition createAndRegisterBeanDefintionWithDefaults(ParserContext parserContext){
		RootBeanDefinition beanDefinition = new RootBeanDefinition(TokenBasedRememberMeServices.class);
		beanDefinition.getPropertyValues().addPropertyValue(KEY, "key");
		parserContext.getReaderContext().registerWithGeneratedName(beanDefinition);
		return beanDefinition;
	}

}
