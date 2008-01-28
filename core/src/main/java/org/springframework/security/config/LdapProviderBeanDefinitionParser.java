package org.springframework.security.config;

import org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

/**
 * Experimental "security:ldap" namespace configuration.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class LdapProviderBeanDefinitionParser implements BeanDefinitionParser {
    private Log logger = LogFactory.getLog(getClass());

    private static final String ATT_AUTH_TYPE = "auth-type";
    private static final String ATT_SERVER = "server-ref";

    private static final String OPT_DEFAULT_DN_PATTERN = "uid={0},ou=people";
    private static final String DEF_GROUP_CONTEXT = "ou=groups";
    private static final String DEF_GROUP_SEARCH_FILTER = "(uniqueMember={0})";


    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        String server = elt.getAttribute(ATT_SERVER);

        if (!StringUtils.hasText(server)) {
            server = BeanIds.CONTEXT_SOURCE;
        }

        RuntimeBeanReference contextSource = new RuntimeBeanReference(server);

        RootBeanDefinition bindAuthenticator = new RootBeanDefinition(BindAuthenticator.class);
        bindAuthenticator.getConstructorArgumentValues().addGenericArgumentValue(contextSource);
        bindAuthenticator.getPropertyValues().addPropertyValue("userDnPatterns", new String[] {OPT_DEFAULT_DN_PATTERN});
        RootBeanDefinition authoritiesPopulator = new RootBeanDefinition(DefaultLdapAuthoritiesPopulator.class);
        authoritiesPopulator.getConstructorArgumentValues().addGenericArgumentValue(contextSource);
        authoritiesPopulator.getConstructorArgumentValues().addGenericArgumentValue(DEF_GROUP_CONTEXT);
        // TODO: Change to using uniqueMember as default
//        authoritiesPopulator.getPropertyValues().addPropertyValue("groupSearchFilter", DEF_GROUP_SEARCH_FILTER);

        RootBeanDefinition ldapProvider = new RootBeanDefinition(LdapAuthenticationProvider.class);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(bindAuthenticator);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(authoritiesPopulator);

        LdapConfigUtils.registerPostProcessorIfNecessary(parserContext.getRegistry());

        ConfigUtils.getRegisteredProviders(parserContext).add(ldapProvider);

        return null;
    }
}
