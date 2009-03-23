package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.Ordered;
import org.springframework.util.ClassUtils;

/**
 * Checks for the presence of a ContextSource instance. Also supplies the standard reference to any
 * unconfigured <ldap-authentication-provider> or <ldap-user-service> beans. This is
 * necessary in cases where the user has given the server a specific Id, but hasn't used
 * the server-ref attribute to link this to the other ldap definitions. See SEC-799.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class ContextSourceSettingPostProcessor implements BeanFactoryPostProcessor, Ordered {
    private static final String REQUIRED_CONTEXT_SOURCE_CLASS_NAME = "org.springframework.ldap.core.support.BaseLdapPathContextSource";

    /** If set to true, a bean parser has indicated that the default context source name needs to be set */
    private boolean defaultNameRequired;


    public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
        Class<?> contextSourceClass;

        try {
            contextSourceClass = ClassUtils.forName(REQUIRED_CONTEXT_SOURCE_CLASS_NAME);
        } catch (ClassNotFoundException e) {
            throw new SecurityConfigurationException("Couldn't locate: " + REQUIRED_CONTEXT_SOURCE_CLASS_NAME + ". " +
                    " If you are using LDAP with Spring Security, please ensure that you include the spring-ldap " +
                    "jar file in your application", e);
        }

        String[] sources = bf.getBeanNamesForType(contextSourceClass);


        if (sources.length == 0) {
            throw new SecurityConfigurationException("No BaseLdapPathContextSource instances found. Have you " +
                    "added an <" + Elements.LDAP_SERVER + " /> element to your application context?");
        }

        if (!bf.containsBean(BeanIds.CONTEXT_SOURCE) && defaultNameRequired) {
            if (sources.length > 1) {
                throw new SecurityConfigurationException("More than one BaseLdapPathContextSource instance found. " +
                        "Please specify a specific server id using the 'server-ref' attribute when configuring your <" +
                        Elements.LDAP_PROVIDER + "> " + "or <" + Elements.LDAP_USER_SERVICE + ">.");
            }

            bf.registerAlias(sources[0], BeanIds.CONTEXT_SOURCE);
        }
    }

    public void setDefaultNameRequired(boolean defaultNameRequired) {
        this.defaultNameRequired = defaultNameRequired;
    }

    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }
}
