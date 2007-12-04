package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.basicauth.BasicProcessingFilterEntryPoint;
import org.w3c.dom.Element;

/**
 * Creates a {@link BasicProcessingFilter} and {@link BasicProcessingFilterEntryPoint} and
 * registers them in the application context.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class BasicAuthenticationBeanDefinitionParser implements BeanDefinitionParser {
	private String realmName;
	
	public BasicAuthenticationBeanDefinitionParser(String realmName) {
		this.realmName = realmName;
	}

	public BeanDefinition parse(Element elt, ParserContext parserContext) {
        BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(BasicProcessingFilter.class);
	    RootBeanDefinition entryPoint = new RootBeanDefinition(BasicProcessingFilterEntryPoint.class);
	
	    entryPoint.getPropertyValues().addPropertyValue("realmName", realmName);
	
	    filterBuilder.addPropertyValue("authenticationEntryPoint", entryPoint);
	    parserContext.getRegistry().registerBeanDefinition(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT, entryPoint);
	    
	    filterBuilder.addPropertyValue("authenticationManager", new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));
	    filterBuilder.addPropertyValue("authenticationEntryPoint", new RuntimeBeanReference(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT));
	    
	    parserContext.getRegistry().registerBeanDefinition(BeanIds.BASIC_AUTHENTICATION_FILTER,
	            filterBuilder.getBeanDefinition());
	
	    return null;
	}
}
