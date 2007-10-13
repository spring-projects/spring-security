package org.springframework.security.config;

import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.util.xml.DomUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author luke
 * @version $Id$
 */
public class AuthenticationProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {
    private static final String DEFAULT_PROVIDER_BEAN_ID = "_authenticationProvider";

    protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {
        RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);

        // TODO: Proper implementation
        Element userServiceElt = DomUtils.getChildElementByTagName(element, "user-service");

        BeanDefinition userDetailsService = new UserServiceBeanDefinitionParser().parse(userServiceElt, parserContext);
        authProvider.getPropertyValues().addPropertyValue("userDetailsService", userDetailsService);

        return authProvider;
    }

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        // TODO: Check for duplicate using default id here.

        return DEFAULT_PROVIDER_BEAN_ID;
    }    

}
