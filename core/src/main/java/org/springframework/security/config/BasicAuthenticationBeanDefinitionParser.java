package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
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
    static final String ATT_REALM = "realm";

	public BeanDefinition parse(Element elt, ParserContext parserContext) {
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(BasicProcessingFilter.class);
        RootBeanDefinition entryPoint = new RootBeanDefinition(BasicProcessingFilterEntryPoint.class);

        String realm = elt.getAttribute(ATT_REALM);

        entryPoint.getPropertyValues().addPropertyValue("realmName", realm);

        filterBuilder.addPropertyValue("authenticationEntryPoint", entryPoint);
        
        // TODO: Remove autowiring approach from here.
        // Detect auth manager
        filterBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.BASIC_AUTHENTICATION_FILTER,
                filterBuilder.getBeanDefinition());
        parserContext.getRegistry().registerBeanDefinition(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT, entryPoint);

        return null;
    }
}
