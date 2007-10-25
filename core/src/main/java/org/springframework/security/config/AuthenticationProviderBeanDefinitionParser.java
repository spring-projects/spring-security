package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
class AuthenticationProviderBeanDefinitionParser implements BeanDefinitionParser {
    public static final String DEFAULT_AUTH_MANAGER_ID = "_authenticationManager";

    private BeanDefinition registerProviderManagerIfNecessary(ParserContext parserContext) {

        if(parserContext.getRegistry().containsBeanDefinition(DEFAULT_AUTH_MANAGER_ID)) {
            return parserContext.getRegistry().getBeanDefinition(DEFAULT_AUTH_MANAGER_ID);
        }

        BeanDefinition authManager = new RootBeanDefinition(ProviderManager.class);
        authManager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(DEFAULT_AUTH_MANAGER_ID, authManager);

        return authManager;
    }

    private ManagedList getRegisteredProviders(ParserContext parserContext) {
        BeanDefinition authManager = registerProviderManagerIfNecessary(parserContext);
        return (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
    }

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        registerProviderManagerIfNecessary(parserContext);

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

        getRegisteredProviders(parserContext).add(authProvider);

        return null;
    }
}
