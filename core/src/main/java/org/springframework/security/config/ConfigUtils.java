package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.security.vote.RoleVoter;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Map;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class ConfigUtils {
    public static final String DEFAULT_ACCESS_MANAGER_ID = "_accessManager";

    static void registerAccessManagerIfNecessary(ConfigurableListableBeanFactory bf) {
        if (bf.getBeanNamesForType(AccessDecisionManager.class).length > 0) {
            return;
        }

        Assert.isInstanceOf(BeanDefinitionRegistry.class, bf, " Auto-registration of default AccessManager will only work " +
                "with a BeanFactory which implements BeanDefinitionRegistry");

        BeanDefinitionRegistry registry = (BeanDefinitionRegistry)bf;

        if (!registry.containsBeanDefinition(DEFAULT_ACCESS_MANAGER_ID)) {
            BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
            accessMgrBuilder.addPropertyValue("decisionVoters",
                            Arrays.asList(new Object[] {new RoleVoter(), new AuthenticatedVoter()}));    
            BeanDefinition accessMgr = accessMgrBuilder.getBeanDefinition();

            registry.registerBeanDefinition(DEFAULT_ACCESS_MANAGER_ID, accessMgr);
        }
    }

    static AuthenticationManager getAuthenticationManager(ConfigurableListableBeanFactory bf) {
        Map authManagers = bf.getBeansOfType(AuthenticationManager.class);

        if (authManagers.size() == 0) {
            throw new IllegalArgumentException("No AuthenticationManager registered. " +
                    "Make sure you have configured at least one AuthenticationProvider?");

        } else if (authManagers.size() > 1) {
            throw new IllegalArgumentException("More than one AuthenticationManager registered.");
        }

        AuthenticationManager accessMgr = (AuthenticationManager) authManagers.values().toArray()[0];

        return accessMgr;
    }

    static void configureSecurityInterceptor(ConfigurableListableBeanFactory beanFactory,
            BeanDefinition securityInterceptor) {
        
        ConfigUtils.registerAccessManagerIfNecessary(beanFactory);

        Map accessManagers = beanFactory.getBeansOfType(AccessDecisionManager.class);

        if (accessManagers.size() > 1) {
            throw new IllegalArgumentException("More than one AccessDecisionManager registered. Please specify one " +
                    "  using the TODO attribute.");
        }

        AccessDecisionManager accessMgr = (AccessDecisionManager) accessManagers.values().toArray()[0];

        securityInterceptor.getPropertyValues().addPropertyValue("accessDecisionManager", accessMgr);
        securityInterceptor.getPropertyValues().addPropertyValue("authenticationManager",
                getAuthenticationManager(beanFactory));
    }
}
