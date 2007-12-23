package org.springframework.security.config;

import org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.SpringSecurityContextSource;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.ui.rememberme.RememberMeServices;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.BeansException;
import org.springframework.core.Ordered;
import org.springframework.ldap.core.ContextSource;
import org.springframework.util.StringUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import java.util.Map;

/**
 * Experimental "security:ldap" namespace configuration.
 *
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
    private static final String DEFAULT_GROUP_CONTEXT = "ou=groups";


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
        authoritiesPopulator.getConstructorArgumentValues().addGenericArgumentValue(DEFAULT_GROUP_CONTEXT);

        RootBeanDefinition ldapProvider = new RootBeanDefinition(LdapAuthenticationProvider.class);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(bindAuthenticator);
        ldapProvider.getConstructorArgumentValues().addGenericArgumentValue(authoritiesPopulator);

        registerPostProcessorIfNecessary(parserContext.getRegistry());

        ConfigUtils.getRegisteredProviders(parserContext).add(ldapProvider);

        return null;
    }

    // Todo: Move to utility class when we add ldap-user-service, as this check will be needed even if no
    // provider is added.
    private static class ContextSourceSettingPostProcessor implements BeanFactoryPostProcessor, Ordered {

        public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
            Map beans = bf.getBeansOfType(SpringSecurityContextSource.class);

            if (beans.size() == 0) {
                throw new SecurityConfigurationException("No SpringSecurityContextSource instances found. Have you " +
                        "added an <" + Elements.LDAP_SERVER + " /> element to your application context?");
            } else if (beans.size() > 1) {
                throw new SecurityConfigurationException("More than one SpringSecurityContextSource instance found. " +
                        "Please specify a specific server id when configuring your <" + Elements.LDAP_PROVIDER + ">");
            }
        }

        public int getOrder() {
            return LOWEST_PRECEDENCE;
        }

    }

    public void registerPostProcessorIfNecessary(BeanDefinitionRegistry registry) {
        if (registry.containsBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR)) {
            return;
        }

        registry.registerBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR,
                new RootBeanDefinition(LdapProviderBeanDefinitionParser.ContextSourceSettingPostProcessor.class));
    }
}
