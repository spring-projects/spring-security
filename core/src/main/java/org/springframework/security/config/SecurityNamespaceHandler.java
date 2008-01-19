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
        // Parsers
    	registerBeanDefinitionParser(Elements.LDAP_PROVIDER, new LdapProviderBeanDefinitionParser());
    	registerBeanDefinitionParser(Elements.LDAP_SERVER, new LdapServerBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.HTTP, new HttpSecurityBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.USER_SERVICE, new UserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.JDBC_USER_SERVICE, new JdbcUserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.AUTHENTICATION_PROVIDER, new AuthenticationProviderBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.ANNOTATION_DRIVEN, new AnnotationDrivenBeanDefinitionParser());

        // Decorators
        registerBeanDefinitionDecorator(Elements.INTERCEPT_METHODS, new InterceptMethodsBeanDefinitionDecorator());
        registerBeanDefinitionDecorator(Elements.FILTER_CHAIN_MAP, new FilterChainMapBeanDefinitionDecorator());
        registerBeanDefinitionDecorator(Elements.USER_FILTER, new OrderedFilterBeanDefinitionDecorator());
    }
}
