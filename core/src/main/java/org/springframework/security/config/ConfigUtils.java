package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.security.vote.RoleVoter;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Map;

/**
 * Utitily methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class ConfigUtils {
    public static final String DEFAULT_ACCESS_MANAGER_ID = "_accessManager";
    public static final String DEFAULT_AUTH_MANAGER_ID = "_authenticationManager";

    static void registerAccessManagerIfNecessary(ConfigurableListableBeanFactory bf) {
        if (bf.getBeanNamesForType(AccessDecisionManager.class).length > 0) {
            return;
        }

        Assert.isInstanceOf(BeanDefinitionRegistry.class, bf, "Auto-registration of default AccessManager will " +
                "only work with a BeanFactory which implements BeanDefinitionRegistry");

        BeanDefinitionRegistry registry = (BeanDefinitionRegistry)bf;

        if (!registry.containsBeanDefinition(DEFAULT_ACCESS_MANAGER_ID)) {
            BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
            accessMgrBuilder.addPropertyValue("decisionVoters",
                            Arrays.asList(new Object[] {new RoleVoter(), new AuthenticatedVoter()}));
            BeanDefinition accessMgr = accessMgrBuilder.getBeanDefinition();

            registry.registerBeanDefinition(DEFAULT_ACCESS_MANAGER_ID, accessMgr);
        }
    }

    /**
     * Creates and registers the bean definition for the default ProviderManager instance and returns
     * the BeanDefinition for it. This method will typically be called when registering authentication providers
     * using the &lt;security:provider /> tag or by other beans which have a dependency on the
     * authentication manager.
     */
    static BeanDefinition registerProviderManagerIfNecessary(ParserContext parserContext) {
        if(parserContext.getRegistry().containsBeanDefinition(DEFAULT_AUTH_MANAGER_ID)) {
            return parserContext.getRegistry().getBeanDefinition(DEFAULT_AUTH_MANAGER_ID);
        }

        BeanDefinition authManager = new RootBeanDefinition(ProviderManager.class);
        authManager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(DEFAULT_AUTH_MANAGER_ID, authManager);

        return authManager;
    }


    /**
     * Supplies the BeanDefinition for an instance of AbstractSecurityInterceptor with the default
     * AccessDecisionManager and AuthenticationManager.
     *
     * @param beanFactory
     * @param securityInterceptor
     */
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

    static UserDetailsService getUserDetailsService(ConfigurableListableBeanFactory bf) {
        Map services = bf.getBeansOfType(UserDetailsService.class);

        if (services.size() == 0) {
            throw new IllegalArgumentException("No UserDetailsService registered.");

        } else if (services.size() > 1) {
            throw new IllegalArgumentException("More than one UserDetailsService registered. Please" +
                    "use a specific Id in your configuration");
        }

        return (UserDetailsService) services.values().toArray()[0];
    }

    private static AuthenticationManager getAuthenticationManager(ConfigurableListableBeanFactory bf) {
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

    static ManagedList getRegisteredProviders(ParserContext parserContext) {
        BeanDefinition authManager = registerProviderManagerIfNecessary(parserContext);
        return (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
    }
}
