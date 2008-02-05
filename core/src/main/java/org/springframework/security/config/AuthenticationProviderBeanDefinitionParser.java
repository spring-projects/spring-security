package org.springframework.security.config;

import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.xml.DomUtils;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * Wraps a UserDetailsService bean with a DaoAuthenticationProvider and registers the latter with the
 * ProviderManager.
 *
 * @author Luke Taylor
 * @version $Id$
 */
class AuthenticationProviderBeanDefinitionParser implements BeanDefinitionParser {
    private static String ATT_USER_DETAILS_REF = "user-service-ref";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);

        Element passwordEncoderElt = DomUtils.getChildElementByTagName(element, Elements.PASSWORD_ENCODER);

        if (passwordEncoderElt != null) {
            PasswordEncoderParser pep = new PasswordEncoderParser(passwordEncoderElt, parserContext);
            authProvider.getPropertyValues().addPropertyValue("passwordEncoder", pep.getPasswordEncoder());

            if (pep.getSaltSource() != null) {
                authProvider.getPropertyValues().addPropertyValue("saltSource", pep.getSaltSource());
            }
        }

        ConfigUtils.getRegisteredProviders(parserContext).add(authProvider);

        String ref = element.getAttribute(ATT_USER_DETAILS_REF);
        Element userServiceElt = DomUtils.getChildElementByTagName(element, Elements.USER_SERVICE);
        Element jdbcUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.JDBC_USER_SERVICE);
        Element ldapUserServiceElt = DomUtils.getChildElementByTagName(element, Elements.LDAP_USER_SERVICE);

        if (StringUtils.hasText(ref)) {
            if (userServiceElt != null || jdbcUserServiceElt != null || ldapUserServiceElt != null) {
                parserContext.getReaderContext().error("The ref attribute cannot be used in combination with child" +
                        "elements '" + Elements.USER_SERVICE + "', '" + Elements.JDBC_USER_SERVICE + "' or '" +
                        Elements.LDAP_USER_SERVICE + "'", element);
            }

            authProvider.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(ref));

            return null;
        }

        // Use the child elements to create the UserDetailsService
        BeanDefinition userDetailsService = null;

        if (userServiceElt != null) {
            userDetailsService = new UserServiceBeanDefinitionParser().parse(userServiceElt, parserContext);
        } else if (jdbcUserServiceElt != null) {
            userDetailsService = new JdbcUserServiceBeanDefinitionParser().parse(jdbcUserServiceElt, parserContext);
        } else if (ldapUserServiceElt != null) {
            userDetailsService = new LdapUserServiceBeanDefinitionParser().parse(ldapUserServiceElt, parserContext);
        } else {
            parserContext.getReaderContext().error("A user-service is required", element);
        }

        authProvider.getPropertyValues().addPropertyValue("userDetailsService", userDetailsService);

        return null;
    }
}
