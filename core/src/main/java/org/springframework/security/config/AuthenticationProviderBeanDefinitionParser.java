package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
class AuthenticationProviderBeanDefinitionParser implements BeanDefinitionParser {

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext);

        RootBeanDefinition authProvider;

        // TODO: Proper implementation
        Element userServiceElt = DomUtils.getChildElementByTagName(element, "user-service");

        if (userServiceElt != null) {
            authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);
            BeanDefinition userDetailsService = new UserServiceBeanDefinitionParser().parse(userServiceElt, parserContext);
            authProvider.getPropertyValues().addPropertyValue("userDetailsService", userDetailsService);
        } else {
            throw new IllegalArgumentException("Only support user-service provider at the moment.");
        }

        ConfigUtils.getRegisteredProviders(parserContext).add(authProvider);

        return null;
    }
}
