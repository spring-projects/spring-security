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
 * @version $Id$
 */
public class BasicAuthenticationBeanDefinitionParser implements BeanDefinitionParser {
    public static final String DEFAULT_BASIC_AUTH_FILTER_ID = "_basicAuthenticationFilter";
    public static final String DEFAULT_BASIC_AUTH_ENTRY_POINT_ID = "_basicAuthenticationEntryPoint";


    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(BasicProcessingFilter.class);
        RootBeanDefinition entryPoint = new RootBeanDefinition(BasicProcessingFilterEntryPoint.class);

        String realm = elt.getAttribute("realm");

        entryPoint.getPropertyValues().addPropertyValue("realmName", realm);

        filterBuilder.addPropertyValue("authenticationEntryPoint", entryPoint);
        // Detect auth manager
        filterBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        parserContext.getRegistry().registerBeanDefinition(DEFAULT_BASIC_AUTH_FILTER_ID,
                filterBuilder.getBeanDefinition());
        parserContext.getRegistry().registerBeanDefinition(DEFAULT_BASIC_AUTH_ENTRY_POINT_ID, entryPoint);

        return null;
    }
}
