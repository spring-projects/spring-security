package org.springframework.security.config;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.authentication.AuthenticationProviderBeanDefinitionParser;
import org.springframework.security.config.authentication.JdbcUserServiceBeanDefinitionParser;
import org.springframework.security.config.authentication.UserServiceBeanDefinitionParser;
import org.springframework.security.config.http.FilterChainMapBeanDefinitionDecorator;
import org.springframework.security.config.http.FilterInvocationSecurityMetadataSourceParser;
import org.springframework.security.config.http.HttpSecurityBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapProviderBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapServerBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapUserServiceBeanDefinitionParser;
import org.springframework.security.config.method.GlobalMethodSecurityBeanDefinitionParser;
import org.springframework.security.config.method.InterceptMethodsBeanDefinitionDecorator;
import org.springframework.util.ClassUtils;

/**
 * Registers the bean definition parsers for the "security" namespace (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @since 2.0
 * @version $Id$
 */
public class SecurityNamespaceHandler extends NamespaceHandlerSupport {

    @SuppressWarnings("deprecation")
    public void init() {
        // Parsers
        registerBeanDefinitionParser(Elements.LDAP_PROVIDER, new LdapProviderBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.LDAP_SERVER, new LdapServerBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.LDAP_USER_SERVICE, new LdapUserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.USER_SERVICE, new UserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.JDBC_USER_SERVICE, new JdbcUserServiceBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.AUTHENTICATION_PROVIDER, new AuthenticationProviderBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.GLOBAL_METHOD_SECURITY, new GlobalMethodSecurityBeanDefinitionParser());
        registerBeanDefinitionParser(Elements.AUTHENTICATION_MANAGER, new AuthenticationManagerBeanDefinitionParser());
        registerBeanDefinitionDecorator(Elements.INTERCEPT_METHODS, new InterceptMethodsBeanDefinitionDecorator());

        // Web-namespace stuff
        if (ClassUtils.isPresent("org.springframework.security.web.FilterChainProxy", ClassUtils.getDefaultClassLoader())) {
            registerBeanDefinitionParser(Elements.HTTP, new HttpSecurityBeanDefinitionParser());
            registerBeanDefinitionDecorator(Elements.FILTER_CHAIN_MAP, new FilterChainMapBeanDefinitionDecorator());
            registerBeanDefinitionParser(Elements.FILTER_INVOCATION_DEFINITION_SOURCE, new FilterInvocationSecurityMetadataSourceParser());
            registerBeanDefinitionParser(Elements.FILTER_SECURITY_METADATA_SOURCE, new FilterInvocationSecurityMetadataSourceParser());
        }
    }

}
