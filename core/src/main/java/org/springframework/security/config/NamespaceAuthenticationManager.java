package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.security.providers.ProviderManager;
import org.springframework.util.Assert;

/**
 * Extended version of {@link ProviderManager the default authentication manager} which lazily initializes
 * the list of {@link AuthenticationProvider}s. This prevents some of the issues that have occurred with 
 * namespace configuration where early instantiation of a security interceptor has caused the AuthenticationManager
 * and thus dependent beans (typically UserDetailsService implementations or DAOs) to be initialized too early. 
 * 
 * @author Luke Taylor
 * @since 2.0.4
 */
public class NamespaceAuthenticationManager extends ProviderManager implements BeanFactoryAware {
	BeanFactory beanFactory;
	List providerBeanNames;
	
	public void setBeanFactory(BeanFactory beanFactory) {
		this.beanFactory = beanFactory;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(providerBeanNames, "provideBeanNames has not been set");
		Assert.notEmpty(providerBeanNames, "No authentication providers were found in the application context");
		
		super.afterPropertiesSet();
	}

	/**
	 * Overridden to lazily-initialize the list of providers on first use.
	 */
	public List getProviders() {
		// We use the names array to determine whether the list has been set yet.
		if (providerBeanNames != null) {
			List providers = new ArrayList();
			Iterator beanNames = providerBeanNames.iterator();
			
			while (beanNames.hasNext()) {
				providers.add(beanFactory.getBean((String) beanNames.next()));
			}
			providerBeanNames = null;
			
			setProviders(providers);
		}
		
		return super.getProviders();
	}

	public void setProviderBeanNames(List provideBeanNames) {
		this.providerBeanNames = provideBeanNames;
	}
}
