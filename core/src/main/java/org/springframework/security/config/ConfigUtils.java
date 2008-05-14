package org.springframework.security.config;

import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.afterinvocation.AfterInvocationProviderManager;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.util.UrlUtils;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.AuthenticatedVoter;
import org.springframework.security.vote.RoleVoter;
import org.springframework.util.StringUtils;

/**
 * Utility methods used internally by the Spring Security namespace configuration code.
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
    
    public static int countNonEmpty(String[] objects) {        
    	int nonNulls = 0;
    	
    	for (int i = 0; i < objects.length; i++) {
    		if (StringUtils.hasText(objects[i])) {
    			nonNulls++;
    		}
    	}
        
    	return nonNulls;
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

    static ManagedList getRegisteredProviders(ParserContext parserContext) {
        BeanDefinition authManager = registerProviderManagerIfNecessary(parserContext);
        return (ManagedList) authManager.getPropertyValues().getPropertyValue("providers").getValue();
    }
    
	static ManagedList getRegisteredAfterInvocationProviders(ParserContext parserContext) {
		BeanDefinition manager = registerAfterInvocationProviderManagerIfNecessary(parserContext);
		return (ManagedList) manager.getPropertyValues().getPropertyValue("providers").getValue();
	}    
    
    private static BeanDefinition registerAfterInvocationProviderManagerIfNecessary(ParserContext parserContext) {
        if(parserContext.getRegistry().containsBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER)) {
            return parserContext.getRegistry().getBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER);
        }

        BeanDefinition manager = new RootBeanDefinition(AfterInvocationProviderManager.class);
        manager.getPropertyValues().addPropertyValue("providers", new ManagedList());
        parserContext.getRegistry().registerBeanDefinition(BeanIds.AFTER_INVOCATION_MANAGER, manager);

        return manager;
	}

	private static void registerFilterChainPostProcessorIfNecessary(ParserContext pc) {
    	if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_POST_PROCESSOR)) {
    		return;
    	}
        // Post processor specifically to assemble and order the filter chain immediately before the FilterChainProxy is initialized.
        RootBeanDefinition filterChainPostProcessor = new RootBeanDefinition(FilterChainProxyPostProcessor.class);
        filterChainPostProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_CHAIN_POST_PROCESSOR, filterChainPostProcessor);
        RootBeanDefinition filterList = new RootBeanDefinition(FilterChainList.class);
        filterList.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_LIST, filterList);
    }
    
    static void addHttpFilter(ParserContext pc, BeanMetadataElement filter) {
    	registerFilterChainPostProcessorIfNecessary(pc);
    	
    	RootBeanDefinition filterList = (RootBeanDefinition) pc.getRegistry().getBeanDefinition(BeanIds.FILTER_LIST);
    	
    	ManagedList filters;
    	MutablePropertyValues pvs = filterList.getPropertyValues();
    	if (pvs.contains("filters")) {
    		filters = (ManagedList) pvs.getPropertyValue("filters").getValue();
    	} else {
    		filters = new ManagedList();
    		pvs.addPropertyValue("filters", filters);
    	}
    	
    	filters.add(filter);
    }

    /**
     * Bean which holds the list of filters which are maintained in the context and modified by calls to 
     * addHttpFilter. The post processor retrieves these before injecting the list into the FilterChainProxy.
     */
    public static class FilterChainList {
    	List filters;

		public List getFilters() {
			return filters;
		}

		public void setFilters(List filters) {
			this.filters = filters;
		}
    }
    
    /**
     * Checks the value of an XML attribute which represents a redirect URL.
     * If not empty or starting with "$" (potential placeholder), "/" or "http" it will raise an error. 
     */
    static void validateHttpRedirect(String url, ParserContext pc, Object source) {
    	if (UrlUtils.isValidRedirectUrl(url) || url.startsWith("$")) {
    		return;
    	}
    	pc.getReaderContext().warning(url + " is not a valid redirect URL (must start with '/' or http(s))", source);
    }
}
