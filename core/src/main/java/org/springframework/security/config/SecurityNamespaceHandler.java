package org.springframework.security.config;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * Registers the bean definition parsers for the "security" namespace (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {    

    public void init() {
        registerBeanDefinitionParser(Elements.LDAP, new LdapBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.HTTP, new HttpSecurityBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.USER_SERVICE, new UserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.REPOSITORY, new RepositoryBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.AUTHENTICATION_PROVIDER, new AuthenticationProviderBeanDefinitionParser());
        registerBeanDefinitionDecorator(Elements.INTERCEPT_METHODS, new InterceptMethodsBeanDefinitionDecorator());
        registerBeanDefinitionDecorator(Elements.FILTER_CHAIN_MAP, new FilterChainMapBeanDefinitionDecorator());        
    }
}
