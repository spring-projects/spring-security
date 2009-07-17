package org.springframework.security.config.method;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.BeanIds;

/**
 * Utility methods used internally by the Spring Security namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id: WebConfigUtils.java 3770 2009-07-15 23:09:47Z ltaylor $
 */
abstract class MethodConfigUtils {
    @SuppressWarnings("unchecked")
    static void registerDefaultMethodAccessManagerIfNecessary(ParserContext parserContext) {
        if (!parserContext.getRegistry().containsBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER)) {
            parserContext.getRegistry().registerBeanDefinition(BeanIds.METHOD_ACCESS_MANAGER,
                    createAccessManagerBean(RoleVoter.class, AuthenticatedVoter.class));
        }
    }

    @SuppressWarnings("unchecked")
    private static RootBeanDefinition createAccessManagerBean(Class<? extends AccessDecisionVoter>... voters) {
        ManagedList defaultVoters = new ManagedList(voters.length);

        for(Class<? extends AccessDecisionVoter> voter : voters) {
            defaultVoters.add(new RootBeanDefinition(voter));
        }

        BeanDefinitionBuilder accessMgrBuilder = BeanDefinitionBuilder.rootBeanDefinition(AffirmativeBased.class);
        accessMgrBuilder.addPropertyValue("decisionVoters", defaultVoters);
        return (RootBeanDefinition) accessMgrBuilder.getBeanDefinition();
    }

    @SuppressWarnings("unchecked")
    static ManagedList getRegisteredAfterInvocationProviders(ParserContext parserContext) {
        BeanDefinition manager = registerAfterInvocationProviderManagerIfNecessary(parserContext);
        return (ManagedList) manager.getPropertyValues().getPropertyValue("providers").getValue();
    }

    @SuppressWarnings("unchecked")
    static BeanDefinition registerAfterInvocationProviderManagerIfNecessary(ParserContext parserContext) {
        if(parserContext.getRegistry().containsBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER)) {
            return parserContext.getRegistry().getBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER);
        }

        BeanDefinition manager = new RootBeanDefinition(AfterInvocationProviderManager.class);
        manager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER, manager);

        return manager;
    }
}
