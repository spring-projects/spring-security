package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.Ordered;
import org.springframework.security.ldap.SpringSecurityContextSource;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
class LdapConfigUtils {

    /** 
     * Checks for the presence of a ContextSource instance. Also supplies the standard reference to any 
     * unconfigured <ldap-authentication-provider> or <ldap-user-service> beans. This is 
     * necessary in cases where the user has given the server a specific Id, but hasn't used
     * the server-ref attribute to link this to the other ldap definitions. See SEC-799.
     */
    private static class ContextSourceSettingPostProcessor implements BeanFactoryPostProcessor, Ordered {
        /** If set to true, a bean parser has indicated that the default context source name needs to be set */  
        private boolean defaultNameRequired;
        
        public void postProcessBeanFactory(ConfigurableListableBeanFactory bf) throws BeansException {
            String[] sources = bf.getBeanNamesForType(SpringSecurityContextSource.class);

            if (sources.length == 0) {
                throw new SecurityConfigurationException("No SpringSecurityContextSource instances found. Have you " +
                        "added an <" + Elements.LDAP_SERVER + " /> element to your application context?");
            }
            
            if (!bf.containsBean(BeanIds.CONTEXT_SOURCE) && defaultNameRequired) {
                if (sources.length > 1) {
                    throw new SecurityConfigurationException("More than one SpringSecurityContextSource instance found. " +
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
    
    static void registerPostProcessorIfNecessary(BeanDefinitionRegistry registry, boolean defaultNameRequired) {
        if (registry.containsBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR)) {
            if (defaultNameRequired) {
                BeanDefinition bd = registry.getBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR);
                bd.getPropertyValues().addPropertyValue("defaultNameRequired", Boolean.valueOf(defaultNameRequired));
            }
            return;
        }

        BeanDefinition bd = new RootBeanDefinition(ContextSourceSettingPostProcessor.class); 
        registry.registerBeanDefinition(BeanIds.CONTEXT_SOURCE_SETTING_POST_PROCESSOR, bd);
        bd.getPropertyValues().addPropertyValue("defaultNameRequired", Boolean.valueOf(defaultNameRequired));
    }

}
