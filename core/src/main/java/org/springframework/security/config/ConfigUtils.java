package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.security.vote.RoleVoter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;

/**
 * Utitily methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public abstract class ConfigUtils {
    private static final Log logger = LogFactory.getLog(ConfigUtils.class);

    static void registerDefaultAccessManagerIfNecessary(ParserContext parserContext) {

        if (!parserContext.getRegistry().containsBeanDefinition(BeanIds.ACCESS_MANAGER)) {
            ManagedList defaultVoters = new ManagedList(2);

            defaultVoters.add(new RootBeanDefinition(RoleVoter.class));
            defaultVoters.add(new RootBeanDefinition(AuthenticatedVoter.class));

            BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
            accessMgrBuilder.addPropertyValue("decisionVoters", defaultVoters);
            BeanDefinition accessMgr = accessMgrBuilder.getBeanDefinition();

            parserContext.getRegistry().registerBeanDefinition(BeanIds.ACCESS_MANAGER, accessMgr);
        }
    }

    public static void addVoter(BeanDefinition voter, ParserContext parserContext) {
        registerDefaultAccessManagerIfNecessary(parserContext);

        BeanDefinition accessMgr = parserContext.getRegistry().getBeanDefinition(BeanIds.ACCESS_MANAGER);

        ManagedList voters = (ManagedList) accessMgr.getPropertyValues().getPropertyValue("decisionVoters").getValue();
        voters.add(voter);
        
        accessMgr.getPropertyValues().addPropertyValue("decisionVoters", voters);
    }

    /**
     * Creates and registers the bean definition for the default ProviderManager instance and returns
     * the BeanDefinition for it. This method will typically be called when registering authentication providers
     * using the &lt;security:provider /> tag or by other beans which have a dependency on the
     * authentication manager.
     */
    static BeanDefinition registerProviderManagerIfNecessary(ParserContext parserContext) {
        if(parserContext.getRegistry().containsBeanDefinition(BeanIds.AUTHENTICATION_MANAGER)) {
            return parserContext.getRegistry().getBeanDefinition(BeanIds.AUTHENTICATION_MANAGER);
        }

        BeanDefinition authManager = new RootBeanDefinition(ProviderManager.class);
        authManager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(BeanIds.AUTHENTICATION_MANAGER, authManager);

        return authManager;
    }


    /**
     * Obtains a user details service for use in RememberMeServices etc. Will return a caching version
     * if available so should not be used for beans which need to separate the two. 
     */
    static UserDetailsService getUserDetailsService(ConfigurableListableBeanFactory bf) {
        Map services = bf.getBeansOfType(CachingUserDetailsService.class);
        
        if (services.size() == 0) {
        	services = bf.getBeansOfType(UserDetailsService.class);
        }

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

        return (AuthenticationManager) authManagers.values().toArray()[0];
    }

    static ManagedList getRegisteredProviders(ParserContext parserContext) {
        BeanDefinition authManager = registerProviderManagerIfNecessary(parserContext);
        return (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
    }
}
