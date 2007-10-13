package org.springframework.security.config;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;


/**
 * Registers the bean definition parsers for the "security" namespace (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {
    public void init() {
        registerBeanDefinitionParser("ldap", new LdapBeanDefinitionParser());
        registerBeanDefinitionParser("http", new HttpSecurityBeanDefinitionParser());
        registerBeanDefinitionParser("authentication-provider", new AuthenticationProviderBeanDefinitionParser());
        registerBeanDefinitionParser("autoconfig", new AutoConfigBeanDefinitionParser());
        registerBeanDefinitionDecorator("intercept-methods", new InterceptMethodsBeanDefinitionDecorator());
    }
}
