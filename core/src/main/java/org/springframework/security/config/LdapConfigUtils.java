package org.springframework.security.config;

import org.springframework.security.ldap.SpringSecurityContextSource;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.BeansException;
import org.springframework.core.Ordered;

import java.util.Map;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
class LdapConfigUtils {

    /** Checks for the presence of a ContextSource instance */
    private static class ContextSourceSettingPostProcessor implements BeanFactoryPostProcessor, Ordered {
        public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
            Map beans = bf.getBeansOfType(SpringSecurityContextSource.class);

            if (beans.size() == 0) {
                throw new SecurityConfigurationException("No SpringSecurityContextSource instances found. Have you " +
                        "added an <" + Elements.LDAP_SERVER + " /> element to your application context?");
            }

//            else if (beans.size() > 1) {
//                throw new SecurityConfigurationException("More than one SpringSecurityContextSource instance found. " +
//                        "Please specify a specific server id when configuring your <" + Elements.LDAP_PROVIDER + "> " +
//                        "or <" + Elements.LDAP_USER_SERVICE + ">.");
//            }
        }

        public int getOrder() {
            return LOWEST_PRECEDENCE;
        }
    }

    static void registerPostProcessorIfNecessary(BeanDefinitionRegistry registry) {
        if (registry.containsBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR)) {
            return;
        }

        registry.registerBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR,
                new RootBeanDefinition(ContextSourceSettingPostProcessor.class));
    }

}
